package applyd

import (
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
    Dest      string
    Interface string
}

func NewVipsManager(runtime *Runtime) *VipsManager {
    p := &VipsManager{}
    return p
}

//func hasIp(dev string, ip string) (found bool, err error) {
//	cmd := exec.Command("/bin/ip", "address", "show", "dev", dev, "to", ip)
//
//	output, err := Execute(cmd)
//    if err != nil {
//	    return err
//    }
//
//	result := strings.TrimSpace(string(output))
//	if result == "" {
//		return false, nil
//	}
//
//	return true, nil
//}

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

func hasIp(dev string, ip net.IP) (found bool, err error) {
    intf, err := net.InterfaceByName(dev)
    if err != nil {
        return false, err
    }

    addrs, err := intf.Addrs()
    if err != nil {
        return false, err
    }

    for _, addr := range addrs {
        addrIp, err := parseIp(addr.String())
        if err != nil {
            return false, err
        }

        //log.Printf("Addr %s %s", dev, addrIp.String())
        if addrIp.Equal(ip) {
            return true, nil
        }
    }

    return false, nil
}

func findIp(ip net.IP) (found string, err error) {
    interfaces, err := net.Interfaces()
    if err != nil {
        return "", err
    }

    for _, intf := range interfaces {
        found, err := hasIp(intf.Name, ip)
        if err != nil {
            return "", err
        }

        if found {
            return intf.Name, nil
        }
    }

    return "", nil
}

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

// TODO: We could probably be more efficient here by using a similar strategy to iptables: collect in bulk
// But, parsing the ip addr show output is painful!
func (s *VipsManager) applyFile(key string, path string) error {
    text, err := gommons.TryReadTextFile(path, "")
    if err != nil {
        return err
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
            return fmt.Errorf("Error parsing line: %s", line)
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
        return err
    }

    if device == "" {
        // Remove the ip
        for {
            foundDevice, err := findIp(ip)
            if err != nil {
                return err
            }

            if foundDevice == "" {
                break
            }

            err = deleteIp(foundDevice, ipString)
            if err != nil {
                return err
            }
        }
    } else {
        // Create the ip
        found, err := hasIp(device, ip)
        if err != nil {
            return err
        }

        if !found {
            err = addIp(device, ipString)
            if err != nil {
                return err
            }
        }
    }

    return nil
}

func (s *VipsManager) apply(basedir string) error {
    files, err := gommons.ListDirectoryNames(basedir)
    if err != nil {
        log.Printf("Error listing files in dir %s: %v", basedir, err)
        return err
    }

    for _, file := range files {
        path := basedir + "/" + file

        err := s.applyFile(file, path)
        if err != nil {
            return err
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
