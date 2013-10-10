package applyd

import (
    "bytes"
    "fmt"
    "github.com/fathomdb/gommons"
    "io/ioutil"
    "log"
    "math/rand"
    "os"
    "os/exec"
    "sort"
    "strings"
)

type IpsetManager struct {
}

type IpsetState struct {
    Ipsets map[string]*Ipset
}

type Ipset struct {
    Name    string
    Spec    string
    Members []string
}

type IpsetMember struct {
    Spec string
}

func NewIpsetManager(firewall *FirewallManager) *IpsetManager {
    p := &IpsetManager{}
    return p
}

func (s *Ipset) normalize() {
    sort.Strings(s.Members)
}

func (s *Ipset) buildConf(changeName *string) string {
    var buffer bytes.Buffer

    name := s.Name
    if changeName != nil {
        name = *changeName
    }

    buffer.WriteString("create " + name + " " + s.Spec + "\n")
    buffer.WriteString("\n")

    for _, member := range s.Members {
        buffer.WriteString("add " + name + " " + member + "\n")
    }

    return buffer.String()
}

func ipsetSave(ruleset *string) (*IpsetState, error) {
    cmd := exec.Command("/usr/sbin/ipset", "save")
    if ruleset != nil {
        cmd.Args = append(cmd.Args, *ruleset)
    }

    output, err := Execute(cmd)
    if err != nil {
        return nil, err
    }

    return parseIpset(string(output))
}

func stringSliceEquals(a []string, b []string) bool {
    if len(a) != len(b) {
        return false
    }

    for i, v := range a {
        if b[i] != v {
            return false
        }
    }
    return true
}

func ipsetMatch(a *Ipset, b *Ipset) bool {
    if a.Spec != b.Spec {
        log.Printf("Spec mismatch on ipset: %v vs %v", a.Spec, b.Spec)
        return false
    }

    sort.Strings(a.Members)
    sort.Strings(b.Members)

    if !stringSliceEquals(a.Members, b.Members) {
        log.Printf("Members mismatch on ipset")
        return false
    }

    return true
}

func parseIpset(spec string) (*IpsetState, error) {
    state := &IpsetState{}
    state.Ipsets = make(map[string]*Ipset)

    for _, line := range strings.Split(spec, "\n") {
        if line == "" {
            continue
        }

        if strings.HasPrefix(line, "create ") {
            fields := strings.Fields(line)
            if len(fields) < 2 {
                return nil, fmt.Errorf("Error parsing line: %s", line)
            }

            name := fields[1]
            ipset := state.Ipsets[name]
            if ipset == nil {
                ipset = &Ipset{}
                ipset.Name = name
                ipset.Spec = strings.Join(fields[2:], " ")

                state.Ipsets[name] = ipset
            } else {
                return nil, fmt.Errorf("Duplicate ipset: %s", name)
            }
        } else if strings.HasPrefix(line, "add ") {
            fields := strings.Fields(line)
            if len(fields) < 2 {
                return nil, fmt.Errorf("Error parsing line: %s", line)
            }

            name := fields[1]
            ipset := state.Ipsets[name]
            if ipset == nil {
                return nil, fmt.Errorf("Ipset not found: %s", name)
            }

            ipset.Members = append(ipset.Members, strings.Join(fields[2:], " "))
        } else {
            return nil, fmt.Errorf("Error parsing line: %s", line)
        }
    }

    for _, ipset := range state.Ipsets {
        ipset.normalize()
    }

    return state, nil
}

func ipsetRestore(conf string, merge bool) (err error) {
    cmd := exec.Command("/usr/sbin/ipset", "restore")
    if merge {
        cmd.Args = append(cmd.Args, "-exist")
    }

    //	var f *os.File
    //	if f, err = os.Open(path); err != nil {
    //		return err
    //	}
    //	defer f.Close()
    cmd.Stdin = bytes.NewBufferString(conf)

    _, err = Execute(cmd)
    if err != nil {
        return err
    }

    return nil
}

func ipsetSwap(a, b string) (err error) {
    cmd := exec.Command("/usr/sbin/ipset", "swap", a, b)

    _, err = Execute(cmd)
    if err != nil {
        return err
    }

    return nil
}

func ipsetDestroy(name string) (err error) {
    cmd := exec.Command("/usr/sbin/ipset", "destroy", name)

    _, err = Execute(cmd)
    if err != nil {
        return err
    }

    return nil
}

func (*IpsetManager) createFiles(state *IpsetState, basedir string) error {
    for name, ipset := range state.Ipsets {
        path := basedir + "/" + name

        conf := ipset.buildConf(nil)

        f, err := gommons.TryReadTextFile(path, "")
        if err != nil {
            return err
        }

        if f == conf {
            continue
        }

        err = ioutil.WriteFile(path, []byte(conf), 0700)
        if err != nil {
            return err
        }
    }

    return nil
}

func readIpsetFile(name string, path string) (state *Ipset, err error) {
    text, err := gommons.TryReadTextFile(path, "")
    if err != nil {
        return nil, err
    }

    ipsetState, err := parseIpset(text)
    if err != nil {
        return nil, err
    }

    if len(ipsetState.Ipsets) > 1 {
        return nil, fmt.Errorf("Found multiple ipsets in file: %s", path)
    }

    ipset := ipsetState.Ipsets[name]
    if ipset == nil {
        return nil, fmt.Errorf("Found ipset with wrong name in file: %s", path)
    }

    return ipset, nil
}

func (s *Ipset) apply(usetemp bool) (err error) {
    // We can't merge; otherwise we can't delete entries
    // We can't delete in case it is in use

    // So we create a new ruleset and then atomically swap them

    if usetemp {
        tmpname := fmt.Sprintf("_applyd_tmp_%x", rand.Int63())

        log.Printf("Creating temp rule and atomically renaming: %v", tmpname)

        conf := s.buildConf(&tmpname)

        err = ipsetRestore(conf, false)
        if err != nil {
            return err
        }

        err = ipsetSwap(tmpname, s.Name)
        if err != nil {
            return err
        }

        err = ipsetDestroy(tmpname)
        if err != nil {
            return err
        }
    } else {
        conf := s.buildConf(nil)

        err = ipsetRestore(conf, false)
        if err != nil {
            return err
        }
    }

    return nil
}

func (s *IpsetManager) ipsetApply(state *IpsetState, basedir string) error {
    files, err := gommons.ListDirectoryNames(basedir)
    if err != nil {
        log.Printf("ipset: Error listing files in dir %s: %v", basedir, err)
        return err
    }

    existingIpsets := make(map[string]*Ipset)

    for k, v := range state.Ipsets {
        existingIpsets[k] = v
    }

    for _, key := range files {
        path := basedir + "/" + key

        fileIpset, err := readIpsetFile(key, path)
        if err != nil {
            return err
        }

        existingIpset := existingIpsets[key]
        if existingIpset != nil {
            delete(existingIpsets, key)

            if ipsetMatch(existingIpset, fileIpset) {
                log.Printf("Configuration match: %s", key)
                continue
            }
        }

        // Configuration needs to be applied
        log.Printf("ipset: Applying changed configuration from disk: %s", key)

        usetemp := existingIpset != nil
        fileIpset.apply(usetemp)
    }

    for k, _ := range existingIpsets {
        // In kernel, not on disk
        log.Printf("ipset: Ignoring %s", k)
    }

    return nil
}

func (s *IpsetManager) Save(basedir string) (err error) {
    ipsetState, err := ipsetSave(nil)
    if err != nil {
        return err
    }

    err = os.MkdirAll(basedir, 0700)
    if err != nil {
        return err
    }

    err = s.createFiles(ipsetState, basedir)
    if err != nil {
        return err
    }

    return nil
}

func (s *IpsetManager) Apply(basedir string) (err error) {
    isdir, err := gommons.IsDirectory(basedir)

    if err != nil {
        return err
    }

    if !isdir {
        log.Printf("ipset: Directory not found; skipping %s", basedir)
        return nil
    }

    ipsetState, err := ipsetSave(nil)
    if err != nil {
        return err
    }

    err = s.ipsetApply(ipsetState, basedir)
    if err != nil {
        return err
    }

    return nil
}
