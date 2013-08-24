package applyd

import (
    "fmt"
    "github.com/fathomdb/gommons"
    "log"
    "os/exec"
    "sort"
    "strings"
)

type IpNeighborProxyManager struct {
    runtime *Runtime
}

type IpNeighborProxyState struct {
    IpNeighborProxies []*IpNeighborProxy
}

type IpNeighborProxy struct {
    Device  string
    Address string
}

func NewIpNeighborProxyManager(runtime *Runtime) *IpNeighborProxyManager {
    p := &IpNeighborProxyManager{}
    p.runtime = runtime
    return p
}

type IpNeighborProxySlice []*IpNeighborProxy

func (s *IpNeighborProxyState) normalize() {
    sort.Sort(IpNeighborProxySlice(s.IpNeighborProxies))
}

func (s IpNeighborProxySlice) Len() int      { return len(s) }
func (s IpNeighborProxySlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s IpNeighborProxySlice) Less(i, j int) bool {
    a := s[i]
    b := s[j]

    if a.Device != b.Device {
        return a.Device < b.Device
    }

    if a.Address != b.Address {
        return a.Address < b.Address
    }

    return false
}

func (a *IpNeighborProxy) matches(b *IpNeighborProxy) bool {
    if a.Address != b.Address {
        return false
    }

    if a.Device != b.Device {
        return false
    }

    return true
}

func (a *IpNeighborProxyState) matches(b *IpNeighborProxyState) bool {
    if len(a.IpNeighborProxies) != len(b.IpNeighborProxies) {
        return false
    }

    for i, a := range a.IpNeighborProxies {
        b := b.IpNeighborProxies[i]

        if !a.matches(b) {
            return false
        }
    }

    return true
}

func (s *IpNeighborProxyManager) parse(spec string) (*IpNeighborProxyState, error) {
    state := &IpNeighborProxyState{}

    for _, line := range strings.Split(spec, "\n") {
        if line == "" {
            continue
        }

        fields := strings.Fields(line)
        if len(fields) == 0 {
            continue
        }

        if strings.HasPrefix(fields[0], "#") {
            continue
        }

        addr := ""
        dev := ""

        for len(fields) > 0 {
            token := fields[0]
            token = strings.ToLower(token)

            if token == "ip" {
                // Ignore
                fields = fields[1:]
            } else if token == "-6" {
                // Ignore
                fields = fields[1:]
            } else if token == "neigh" {
                // Ignore
                fields = fields[1:]
            } else if token == "add" {
                // Ignore
                fields = fields[1:]
            } else if token == "proxy" {
                if len(fields) < 2 {
                    return nil, fmt.Errorf("Error parsing line: %s", line)
                }

                addr = fields[1]
                fields = fields[2:]
            } else if token == "dev" {
                if len(fields) < 2 {
                    return nil, fmt.Errorf("Error parsing line: %s", line)
                }

                dev = fields[1]
                fields = fields[2:]
            } else {
                return nil, fmt.Errorf("Cannot parse line %s", line)
            }
        }

        if addr != "" {
            proxy := &IpNeighborProxy{}
            proxy.Address = addr
            proxy.Device = dev
            state.IpNeighborProxies = append(state.IpNeighborProxies, proxy)
        }
    }

    state.normalize()

    return state, nil
}

func (s *IpNeighborProxy) apply() (err error) {
    cmd := exec.Command("/sbin/ip", "-6", "neigh", "add", "proxy", s.Address)
    if s.Device != "" {
        cmd.Args = append(cmd.Args, "dev", s.Device)
    }

    if _, err = cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("Error running neighbour proxy command: %s", err)
    }

    return nil
}

func (s *IpNeighborProxyManager) readFile(path string) (*IpNeighborProxyState, error) {
    text, err := gommons.TryReadFile(path, "")
    if err != nil {
        return nil, err
    }

    state, err := s.parse(text)
    if err != nil {
        return nil, err
    }

    return state, nil
}

func (s *IpNeighborProxyState) apply() (err error) {
    for _, proxy := range s.IpNeighborProxies {
        err = proxy.apply()
        if err != nil {
            return err
        }
    }

    return nil
}

func (s *IpNeighborProxyManager) apply(state *IpNeighborProxyState, basedir string) error {
    files, err := gommons.ListDirectory(basedir)
    if err != nil {
        log.Printf("ipset: Error listing files in dir %s: %v", basedir, err)
        return err
    }

    for _, file := range files {
        key := file.Name()
        path := basedir + "/" + key

        state, err := s.readFile(path)
        if err != nil {
            return err
        }

        // Configuration needs to be applied
        // There's no way to find out the current config!
        log.Printf("ip neigh: Applying %s", key)

        err = state.apply()
        if err != nil {
            return err
        }
    }

    return nil
}

func (s *IpNeighborProxyManager) Apply(basedir string) (err error) {
    isdir, err := gommons.IsDirectory(basedir)
    if err != nil {
        return err
    }

    if !isdir {
        log.Printf("ip6neigh: Directory not found; skipping %s", basedir)
        return nil
    }

    //	ipsetState, err := ipsetSave(nil)
    //	if err != nil {
    //		return err
    //	}

    err = s.apply(nil, basedir)
    if err != nil {
        return err
    }

    return nil
}
