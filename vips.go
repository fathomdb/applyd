package applyd

import (
    "bytes"
    "fmt"
    "github.com/fathomdb/gommons"
    "log"
    "net"
    "os/exec"
    "strings"
)

type VipsManager struct {
}

type VipsState struct {
    Ips map[string]*Vip
}

type Vip struct {
    Ip        string
    Interface string
}

type IpState struct {
    Ips []InterfaceIp
}

type InterfaceIp struct {
    Ip        net.IP
    Interface string
}

func NewVipsManager(runtime *Runtime) *VipsManager {
    p := &VipsManager{}
    return p
}

func isIpv4(ip net.IP) bool {
    ipv4 := ip.To4()
    return ipv4 != nil
}

func parseIp(s string) (ip net.IP, err error) {
    if strings.Contains(s, "/") {
        ip, _, err = net.ParseCIDR(s)
        if err != nil {
            return nil, err
        }
    } else {
        ip = net.ParseIP(s)
    }
    return ip, nil
}

func buildIpMap() (state *IpState, err error) {
    cmd := exec.Command("/bin/ip", "--oneline", "address", "show")

    output, err := Execute(cmd)
    if err != nil {
        return nil, err
    }

    state = &IpState{}
    state.Ips = make([]InterfaceIp, 0)

    for _, line := range strings.Split(string(output), "\n") {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        fields := strings.Fields(line)
        if len(fields) < 3 {
            return nil, fmt.Errorf("Error parsing line: %s", line)
        }

        nettype := fields[2]
        if nettype != "inet" && nettype != "inet6" {
            continue
        }

        if len(fields) < 4 {
            return nil, fmt.Errorf("Error parsing line: %s", line)
        }
        intf := fields[1]
        cidr := fields[3]

        vip := InterfaceIp{}
        vip.Interface = intf
        ip, err := parseIp(cidr)
        if err != nil {
            log.Print("Error parsing line: ", line)
            return nil, err
        }
        vip.Ip = ip

        state.Ips = append(state.Ips, vip)
    }

    return state, nil
}

// It would probably be more efficient to build the ip map using the direct function
// But there's a golang bug that's blocking us: https://code.google.com/p/go/issues/detail?id=6433
//func hasIp(dev string, ip net.IP) (found bool, err error) {
//    intf, err := net.InterfaceByName(dev)
//    if err != nil {
//        return false, err
//    }
//
//    addrs, err := intf.Addrs()
//    if err != nil {
//        return false, err
//    }
//
//    for _, addr := range addrs {
//        addrIp, err := parseIp(addr.String())
//        if err != nil {
//            return false, err
//        }
//
//        //log.Printf("Addr %s %s", dev, addrIp.String())
//        if addrIp.Equal(ip) {
//            return true, nil
//        }
//    }
//
//    return false, nil
//}
//func findIp(ip net.IP) (found string, err error) {
//    interfaces, err := net.Interfaces()
//    if err != nil {
//        return "", err
//    }
//
//    for _, intf := range interfaces {
//        found, err := hasIp(intf.Name, ip)
//        if err != nil {
//            return "", err
//        }
//
//        if found {
//            return intf.Name, nil
//        }
//    }
//
//    return "", nil
//}

func addIp(dev string, ip string) (err error) {
    log.Printf("vips: Adding %s %s", dev, ip)

    args := make([]string, 0)
    if strings.Contains(ip, ":") {
        args = append(args, "-6")
    }

    args = append(args, "address", "add", ip, "dev", dev)

    cmd := exec.Command("/bin/ip", args...)

    _, err = Execute(cmd)
    if err != nil {
        return err
    }

    return nil
}

func deleteIp(dev string, ip string) (err error) {
    log.Printf("vips: Deleting %s %s", dev, ip)

    args := make([]string, 0)
    if strings.Contains(ip, ":") {
        args = append(args, "-6")
    }

    args = append(args, "address", "delete", ip, "dev", dev)

    cmd := exec.Command("/bin/ip", args...)

    _, err = Execute(cmd)
    if err != nil {
        return err
    }

    return nil
}

func (s *IpState) findDevicesWithIp(ip net.IP) (devices []string, err error) {
    devices = make([]string, 0)

    for _, vip := range s.Ips {
        if bytes.Equal(vip.Ip, ip) {
            devices = append(devices, vip.Interface)
        }
    }

    return devices, nil
}

func (s *IpState) hasIp(ip net.IP, device string) (found bool, err error) {
    devices, err := s.findDevicesWithIp(ip)
    if err != nil {
        return false, err
    }

    for _, d := range devices {
        if device == d {
            return true, nil
        }
    }

    return false, nil
}

func (s *VipsManager) applyFile(state *IpState, key string, path string) (changed bool, err error) {
    changed = false

    text, err := gommons.TryReadTextFile(path, "")
    if err != nil {
        return changed, err
    }

    var device string
    var ipString string

    for _, line := range strings.Split(text, "\n") {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        fields := strings.Fields(line)
        if len(fields) < 1 || len(fields) > 2 {
            return changed, fmt.Errorf("Error parsing line: %s", line)
        }

        device = fields[0]
        if len(fields) >= 2 {
            ipString = fields[1]
        }
    }

    if ipString == "" {
        if strings.Contains(key, ":") {
            ipString = key + "/128"
        } else {
            ipString = key + "/32"
        }
    }

    ip, err := parseIp(ipString)
    if err != nil {
        return changed, err
    }

    if device == "" {
        // Remove the ip
        for {
            devices, err := state.findDevicesWithIp(ip)
            if err != nil {
                return changed, err
            }

            for _, device := range devices {
                err = deleteIp(device, ipString)
                if err != nil {
                    return changed, err
                }
            }
            changed = true
        }
    } else {
        // Create the ip
        found, err := state.hasIp(ip, device)
        if err != nil {
            return changed, err
        }

        if !found {
            err = addIp(device, ipString)
            if err != nil {
                return changed, err
            }
            changed = true
        }
    }

    return changed, err
}

func (s *VipsManager) apply(basedir string) error {
    files, err := gommons.ListDirectoryNames(basedir)
    if err != nil {
        log.Printf("Error listing files in dir %s: %v", basedir, err)
        return err
    }

    var state *IpState

    for _, file := range files {
        if state == nil {
            state, err = buildIpMap()
            if err != nil {
                log.Print("Unable to collect IP state: ", err)

                return err
            }
        }

        path := basedir + "/" + file

        changed, err := s.applyFile(state, file, path)
        if err != nil {
            return err
        }

        if changed {
            state = nil
        }
    }

    return nil
}

func (s *VipsManager) Apply(basedir string) (err error) {
    isdir, err := gommons.IsDirectory(basedir)
    if err != nil {
        return err
    }

    if !isdir {
        log.Printf("Vips: Directory not found; skipping %s", basedir)
        return nil
    }

    err = s.apply(basedir)
    if err != nil {
        return err
    }

    return nil
}
