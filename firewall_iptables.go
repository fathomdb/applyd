package applyd

import (
    "bytes"
    "fmt"
    "github.com/fathomdb/gommons"
    "io"
    "io/ioutil"
    "log"
    "os"
    "os/exec"
    "strings"
)

type IptablesManager struct {
    Ipv6 bool
}

type IptablesState struct {
    Ipv6   bool
    Tables map[string]*IptablesTable
}

type IptablesTable struct {
    Name   string
    Chains map[string]*IptablesChain
}

type IptablesChain struct {
    Name    string
    Default string
    Rules   []*IptablesRule
}

type IptablesRule struct {
    Spec string
}

func NewIptablesManager(firewall *FirewallManager, ipv6 bool) *IptablesManager {
    p := &IptablesManager{}
    p.Ipv6 = ipv6
    return p
}

func (s *IptablesState) normalize() (err error) {
    for _, table := range s.Tables {
        table.normalize(s.Ipv6)
    }

    return nil
}

func (s *IptablesTable) normalize(ipv6 bool) (err error) {
    for _, chain := range s.Chains {
        chain.normalize(ipv6)
    }

    return nil
}

func (s *IptablesChain) normalize(ipv6 bool) (err error) {
    if s.Default == "" {
        s.Default = "-"
    }

    for _, rule := range s.Rules {
        rule.normalize(ipv6)
    }

    return nil
}

func (s *IptablesRule) normalize(ipv6 bool) (err error) {
    fields := strings.Fields(s.Spec)

    i := 0
    for i < len(fields) {
        f := fields[i]
        if f == "-p" {
            if (i + 1) < len(fields) {
                protocol := fields[i+1]
                if protocol == "icmpv6" {
                    fields[i+1] = "ipv6-icmp"
                }
                i++
            }
        } else if f == "-d" || f == "-s" {
            if (i + 1) < len(fields) {
                addr := fields[i+1]
                if !strings.Contains(addr, "/") {
                    if ipv6 {
                        addr = addr + "/128"
                    } else {
                        addr = addr + "/32"
                    }
                    fields[i+1] = addr
                }

                if addr == "0.0.0.0/0" {
                    fields[i] = ""
                    addr = ""
                    fields[i+1] = addr
                }

                i++
            }
        }

        i++
    }

    // Remove any empty strings
    f2 := make([]string, len(fields))
    i = 0
    for _, f := range fields {
        if f == "" {
            continue
        }
        f2[i] = f
        i++
    }

    s.Spec = strings.Join(f2[0:i], " ")

    return nil
}

func (s *IptablesState) writeConf(w io.Writer) (err error) {
    for _, table := range s.Tables {
        err = table.writeConf(w)
        if err != nil {
            return err
        }
    }

    return nil
}

func (s *IptablesState) conf() (string, error) {
    var buffer bytes.Buffer

    err := s.writeConf(&buffer)
    if err != nil {
        return "", err
    }

    conf := buffer.String()
    return conf, nil
}

func (s *IptablesTable) writeConf(w io.Writer) (err error) {
    _, err = io.WriteString(w, "*"+s.Name+"\n")
    if err != nil {
        return err
    }

    for _, chain := range s.Chains {
        err = chain.writeConfDefault(w)
        if err != nil {
            return err
        }
    }

    for _, chain := range s.Chains {
        err = chain.writeConfRules(w)
        if err != nil {
            return err
        }
    }

    _, err = io.WriteString(w, "COMMIT\n")
    if err != nil {
        return err
    }
    return nil
}

func (s *IptablesChain) writeConfDefault(w io.Writer) (err error) {
    action := s.Default
    if action == "" {
        action = "-"
    }

    _, err = io.WriteString(w, ":"+s.Name+" "+action+"\n")
    if err != nil {
        return err
    }

    return nil
}

func (s *IptablesChain) writeConfRules(w io.Writer) (err error) {
    for _, rule := range s.Rules {
        err = rule.writeConf(s.Name, w)
        if err != nil {
            return err
        }
    }

    return nil
}

func (s *IptablesRule) writeConf(chain string, w io.Writer) (err error) {
    _, err = io.WriteString(w, "-A "+chain+" "+s.Spec+"\n")
    if err != nil {
        return err
    }

    return nil
}

func iptablesSave(ipv6 bool) (*IptablesState, error) {
    name := "/sbin/iptables-save"
    if ipv6 {
        name = "/sbin/ip6tables-save"
    }

    cmd := exec.Command(name)

    output, err := Execute(cmd)
    if err != nil {
        return nil, err
    }

    return parseIptablesSave(ipv6, string(output))
}

func parseIptablesSave(ipv6 bool, spec string) (*IptablesState, error) {
    state := &IptablesState{}
    state.Ipv6 = ipv6
    state.Tables = make(map[string]*IptablesTable)

    var currentTable *IptablesTable

    for _, line := range strings.Split(spec, "\n") {
        if line == "" {
            continue
        }

        if strings.HasPrefix(line, "#") {
            continue
        }

        if strings.HasPrefix(line, "*") {
            name := line[1:]

            table := state.Tables[name]
            if table == nil {
                table = &IptablesTable{}
                table.Name = name
                table.Chains = make(map[string]*IptablesChain)

                state.Tables[name] = table

                currentTable = table
            } else {
                return nil, fmt.Errorf("Duplicate table: %s", name)
            }
        } else if strings.HasPrefix(line, ":") {
            fields := strings.Fields(line[1:])
            if len(fields) < 2 {
                return nil, fmt.Errorf("Error parsing line: %s", line)
            }

            name := fields[0]

            if currentTable == nil {
                return nil, fmt.Errorf("No current table at line: %s", line)
            }

            chain := currentTable.Chains[name]
            if chain == nil {
                chain = &IptablesChain{}
                chain.Name = name
                chain.Default = fields[1]

                currentTable.Chains[name] = chain
            } else {
                return nil, fmt.Errorf("Duplicate chain: %s", name)
            }
        } else if strings.HasPrefix(line, "-A ") {
            fields := strings.Fields(line[3:])
            if len(fields) < 1 {
                return nil, fmt.Errorf("Error parsing line: %s", line)
            }

            name := fields[0]

            if currentTable == nil {
                return nil, fmt.Errorf("No current table at line: %s", line)
            }

            chain := currentTable.Chains[name]
            if chain == nil {
                chain = &IptablesChain{}
                chain.Name = name

                currentTable.Chains[name] = chain
            }

            rule := &IptablesRule{}
            rule.Spec = strings.Join(fields[1:], " ")

            chain.Rules = append(chain.Rules, rule)
        } else if line == "COMMIT" {
            if currentTable == nil {
                return nil, fmt.Errorf("Unexpected COMMIT found")
            }
            currentTable = nil
        } else {
            return nil, fmt.Errorf("Error parsing line: %s", line)
        }
    }

    err := state.normalize()
    if err != nil {
        return nil, err
    }

    return state, nil
}

func iptablesRestore(ipv6 bool, conf string) (err error) {
    name := "/sbin/iptables-restore"
    if ipv6 {
        name = "/sbin/ip6tables-restore"
    }
    cmd := exec.Command(name)

    cmd.Stdin = bytes.NewBufferString(conf)

    _, err = Execute(cmd)
    if err != nil {
        return err
    }

    return nil
}

func (s *IptablesManager) Save(basedir string) (err error) {
    state, err := iptablesSave(s.Ipv6)
    if err != nil {
        return err
    }

    err = os.MkdirAll(basedir, 0700)
    if err != nil {
        return err
    }

    err = s.createFiles(state, basedir)
    if err != nil {
        return err
    }

    return nil
}

func (s *IptablesManager) Apply(basedir string) (err error) {
    isdir, err := gommons.IsDirectory(basedir)
    if err != nil {
        return err
    }

    if !isdir {
        log.Printf("iptables: Directory not found; skipping %s", basedir)
        return nil
    }

    current, err := iptablesSave(s.Ipv6)
    if err != nil {
        return err
    }

    err = s.apply(current, basedir)
    if err != nil {
        return err
    }

    return nil
}

func (*IptablesManager) createFiles(state *IptablesState, basedir string) error {
    var path string
    path = basedir + "/10-saved"

    conf, err := state.conf()
    if err != nil {
        return err
    }

    f, err := gommons.TryReadFile(path, "")
    if err != nil {
        return err
    }

    if f == conf {
        return nil
    }

    err = ioutil.WriteFile(path, []byte(conf), 0700)
    if err != nil {
        return err
    }

    return nil
}

func readIptablesFile(ipv6 bool, path string) (state *IptablesState, err error) {
    text, err := gommons.TryReadFile(path, "")
    if err != nil {
        return nil, err
    }

    state, err = parseIptablesSave(ipv6, text)
    if err != nil {
        return nil, err
    }

    return state, nil
}

func (s *IptablesState) apply() (err error) {
    conf, err := s.conf()
    if err != nil {
        return err
    }

    err = iptablesRestore(s.Ipv6, conf)
    if err != nil {
        return err
    }

    return nil
}

func (a *IptablesState) matches(b *IptablesState) bool {
    if a.Ipv6 != b.Ipv6 {
        return false
    }

    if len(a.Tables) != len(b.Tables) {
        return false
    }

    for k, av := range a.Tables {
        bv, exists := b.Tables[k]
        if !exists {
            return false
        }

        if !av.matches(bv) {
            return false
        }
    }

    return true
}

func (a *IptablesTable) matches(b *IptablesTable) bool {
    if a.Name != b.Name {
        return false
    }

    if len(a.Chains) != len(b.Chains) {
        return false
    }

    for k, av := range a.Chains {
        bv, exists := b.Chains[k]
        if !exists {
            return false
        }

        if !av.matches(bv) {
            return false
        }
    }

    return true
}

func (a *IptablesChain) matches(b *IptablesChain) bool {
    if a.Name != b.Name {
        return false
    }

    if a.Default != b.Default {
        return false
    }

    if len(a.Rules) != len(b.Rules) {
        return false
    }

    for i, av := range a.Rules {
        bv := b.Rules[i]
        if !av.matches(bv) {
            return false
        }
    }

    return true
}

func (a *IptablesRule) matches(b *IptablesRule) bool {
    if a.Spec != b.Spec {
        log.Printf("Rule mismatch %s vs %s", a.Spec, b.Spec)
        return false
    }

    return true
}

func (a *IptablesState) merge(b *IptablesState) error {
    if a.Ipv6 != b.Ipv6 {
        return fmt.Errorf("Cannot merge IPv4 & IPv6 tables")
    }

    for k, bv := range b.Tables {
        av := a.Tables[k]
        if av == nil {
            a.Tables[k] = bv
        } else {
            err := av.merge(bv)
            if err != nil {
                return err
            }
        }
    }

    return nil
}

func (a *IptablesTable) merge(b *IptablesTable) error {
    if a.Name != b.Name {
        return fmt.Errorf("Mismatch in merge")
    }

    for k, bv := range b.Chains {
        av := a.Chains[k]
        if av == nil {
            a.Chains[k] = bv
        } else {
            err := av.merge(bv)
            if err != nil {
                return err
            }
        }
    }

    return nil
}

func (a *IptablesChain) merge(b *IptablesChain) error {
    if a.Name != b.Name {
        return fmt.Errorf("Mismatch in merge")
    }

    if a.Default != b.Default {
        if a.Default == "" || a.Default == "-" {
            a.Default = b.Default
        } else if b.Default == "" || b.Default == "-" {
            // Keep what we've got
        } else {
            // TODO: Not entirely clear what we should do here
            log.Printf("Merging different defaults for chain: %s (%s vs %s)", a.Name, a.Default, b.Default)

            // We just allow overwriting
            a.Default = b.Default
        }
    }

    if a.Default == "" {
        a.Default = "-"
    }

    a.Rules = append(a.Rules, b.Rules...)

    return nil
}

func (s *IptablesManager) command() string {
    if s.Ipv6 {
        return "ip6tables"
    }
    return "iptables"
}

func (s *IptablesManager) apply(current *IptablesState, basedir string) error {
    files, err := gommons.ListDirectoryNames(basedir)
    if err != nil {
        log.Printf("Error listing files in dir %s: %v", basedir, err)
        return err
    }

    var desired *IptablesState

    for _, file := range files {
        path := basedir + "/" + file

        state, err := readIptablesFile(current.Ipv6, path)
        if err != nil {
            return err
        }

        //		c, _ := state.conf()
        //		log.Printf("Loaded %s; %v", path, c)

        if desired == nil {
            desired = state
        } else {
            desired.merge(state)
        }

        //		c, _ = desired.conf()
        //		log.Printf("merged %v", c)
    }

    if desired == nil {
        log.Printf("%s: No configuration found", s.command())
        return nil
    }

    if desired.matches(current) {
        //log.Printf("%s: Configuration matches", s.command())
        return nil
    }

    {
        c, _ := current.conf()
        log.Printf("Old configuration %s", c)
    }

    {
        c, _ := desired.conf()
        log.Printf("New configuration %s", c)
    }

    log.Printf("%s: Applying new configuration", s.command())

    return desired.apply()
}
