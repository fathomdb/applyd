package applyd

import (
    "fmt"
    "log"
    "os/exec"
    "strings"
)

type PackageManager struct {
    runtime *Runtime
}

type PackageInfo struct {
    Name  string
    State string
}

func NewPackageManager(runtime *Runtime) *PackageManager {
    p := &PackageManager{}
    p.runtime = runtime
    return p
}

func (*PackageManager) List() ([]*PackageInfo, error) {
    cmd := exec.Command("/usr/bin/dpkg", "--get-selections")
    output, err := cmd.CombinedOutput()
    if err != nil {
        return nil, fmt.Errorf("Error running dpkg: %s", err)
    }

    ret := []*PackageInfo{}

    for _, line := range strings.Split(string(output), "\n") {
        fields := strings.Fields(line)
        if len(fields) == 0 {
            // Ignore blank lines
            continue
        }
        if len(fields) != 2 {
            return nil, fmt.Errorf("Error parsing line: %s", line)
        }

        p := &PackageInfo{}
        p.Name = fields[0]
        p.State = fields[1]

        ret = append(ret, p)
    }

    return ret, nil
}

func (*PackageManager) Install(packages ...string) ([]*PackageInfo, error) {
    cmd := exec.Command("apt-get", "install", "--yes")
    cmd.Args = append(cmd.Args, packages...)

    output, err := cmd.CombinedOutput()
    if err != nil {
        return nil, fmt.Errorf("Error running apt-get install: %s", err)
    }

    log.Printf("Output from install: %s", output)

    ret := []*PackageInfo{}

    return ret, nil
}
