package applyd

import (
    "fmt"
    "github.com/fathomdb/gommons"
    "log"
    "os/exec"
    "strings"
)

type TunnelsManager struct {
}

type TunnelsState struct {
    Tunnels map[string]*Tunnel
}

type Tunnel struct {
    Name   string
    Remote string
    Local  string
    Mode   string
}

func NewTunnelsManager(runtime *Runtime) *TunnelsManager {
    p := &TunnelsManager{}
    return p
}

func parseTunnel(line string) (t *Tunnel, err error) {
    line = strings.TrimSpace(line)

    fields := strings.Fields(line)
    if len(fields) < 1 {
        return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
    }

    t = &Tunnel{}

    mode := fields[0]
    if mode == "ipv6/ipv6" {
        t.Mode = "ip6ip6"
    } else {
        return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
    }

    i := 1
    for i < len(fields) {
        f := fields[i]
        if f == "remote" {
            if (i + 1) < len(fields) {
                t.Remote = fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
            }
        } else if f == "local" {
            if (i + 1) < len(fields) {
                t.Local = fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
            }
        } else if f == "encaplimit" {
            if (i + 1) < len(fields) {
                //t.encaplimit := fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
            }
        } else if f == "hoplimit" {
            if (i + 1) < len(fields) {
                //t.hoplimit := fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
            }
        } else if f == "tclass" {
            if (i + 1) < len(fields) {
                //t.tclass := fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
            }
        } else if f == "flowlabel" {
            if (i + 1) < len(fields) {
                //t.flowlabel := fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
            }
        } else if f == "(flowinfo" {
            if (i + 1) < len(fields) {
                //t.flowinfo := fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
            }
        } else {
            return nil, fmt.Errorf("Error parsing tunnel spec: %s", line)
        }

        i++
    }

    return t, nil
}

func readTunnelFile(name string, path string) (tunnel *Tunnel, err error) {
    text, err := gommons.TryReadTextFile(path, "")
    if err != nil {
        return nil, err
    }

    tunnel, err = parseTunnel(text)
    if err != nil {
        return nil, err
    }

    tunnel.Name = name
    return tunnel, nil
}

func showTunnels() (state *TunnelsState, err error) {
    cmd := exec.Command("/sbin/ip", "-6", "tunnel", "show")

    output, err := Execute(cmd)
    if err != nil {
        return nil, err
    }

    state = &TunnelsState{}
    state.Tunnels = make(map[string]*Tunnel)

    for _, line := range strings.Split(string(output), "\n") {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        fields := strings.Fields(line)
        if len(fields) < 2 {
            return nil, fmt.Errorf("Error parsing line: %s", line)
        }

        name := fields[0]
        if !strings.HasSuffix(name, ":") {
            return nil, fmt.Errorf("Error parsing line: %s", line)
        }
        name = strings.TrimRight(name, ":")

        t, err := parseTunnel(strings.Join(fields[1:], " "))
        if err != nil {
            return nil, err
        }

        t.Name = name
        state.Tunnels[name] = t
    }

    return state, nil
}

func tunnelMatch(l, r *Tunnel) bool {
    if l.Mode != r.Mode {
        return false
    }
    if l.Local != r.Local {
        return false
    }
    if l.Remote != r.Remote {
        return false
    }
    return true
}

func (s *Tunnel) apply() (err error) {
    log.Printf("tunnel: Creating %s", s.Name)

    cmd := exec.Command("/sbin/ip", "-6", "tunnel", "add", s.Name)
    if s.Mode != "" {
        cmd.Args = append(cmd.Args, "mode", s.Mode)
    }
    if s.Local != "" {
        cmd.Args = append(cmd.Args, "local", s.Local)
    }
    if s.Remote != "" {
        cmd.Args = append(cmd.Args, "remote", s.Remote)
    }

    _, err = Execute(cmd)
    if err != nil {
        return err
    }

    return nil
}

func (s *TunnelsManager) apply(state *TunnelsState, basedir string) error {
    files, err := gommons.ListDirectoryNames(basedir)
    if err != nil {
        log.Printf("tunnel: Error listing files in dir %s: %v", basedir, err)
        return err
    }

    existingTunnels := make(map[string]*Tunnel)

    for k, v := range state.Tunnels {
        existingTunnels[k] = v
    }

    for _, key := range files {
        path := basedir + "/" + key

        fileTunnel, err := readTunnelFile(key, path)
        if err != nil {
            return err
        }

        existingTunnel := existingTunnels[key]
        if existingTunnel != nil {
            delete(existingTunnels, key)

            if tunnelMatch(existingTunnel, fileTunnel) {
                log.Printf("Configuration match: %s", key)
                continue
            }
        }

        // Configuration needs to be applied
        log.Printf("tunnel: Applying changed configuration from disk: %s", key)

        fileTunnel.apply()
    }

    for k, _ := range existingTunnels {
        // Configured in kernel, not on disk
        log.Printf("tunnel: Ignoring %s", k)
    }

    return nil
}

func (s *TunnelsManager) Apply(basedir string) (err error) {
    isdir, err := gommons.IsDirectory(basedir)
    if err != nil {
        return err
    }

    if !isdir {
        log.Printf("tunnels: Directory not found; skipping %s", basedir)
        return nil
    }

    current, err := showTunnels()
    if err != nil {
        return err
    }

    err = s.apply(current, basedir)
    if err != nil {
        return err
    }

    return nil
}
