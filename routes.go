package applyd

import (
    "fmt"
    "github.com/fathomdb/gommons"
    "log"
    "os/exec"
    "strings"
)

type RoutesManager struct {
    Ipv6 bool
}

type RoutesState struct {
    Routes []*Route
}

type Route struct {
    Spec string

    Dest      string
    Src       string
    Protocol  string
    Metric    string
    ErrorCode string
    Via       string
    Scope     string
    Device    string
}

func NewRoutesManager(runtime *Runtime, ipv6 bool) *RoutesManager {
    p := &RoutesManager{}
    p.Ipv6 = ipv6
    return p
}

func parseRoute(line string) (r *Route, err error) {
    line = strings.TrimSpace(line)

    fields := strings.Fields(line)
    if len(fields) < 1 {
        return nil, fmt.Errorf("Error parsing route spec: %s", line)
    }

    r = &Route{}

    dest := fields[0]
    if dest == "unreachable" {
        fields = fields[1:]
        if len(fields) < 1 {
            return nil, fmt.Errorf("Error parsing route spec: %s", line)
        }
        dest = fields[0]
    }
    r.Dest = dest

    i := 1
    for i < len(fields) {
        f := fields[i]
        if f == "dev" {
            if (i + 1) < len(fields) {
                r.Device = fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing route spec (dev): %s", line)
            }
        } else if f == "proto" {
            if (i + 1) < len(fields) {
                r.Protocol = fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing route spec (proto): %s", line)
            }
        } else if f == "metric" {
            if (i + 1) < len(fields) {
                r.Metric = fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing route spec (metric): %s", line)
            }
        } else if f == "error" {
            if (i + 1) < len(fields) {
                r.ErrorCode = fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing route spec (error): %s", line)
            }
        } else if f == "via" {
            if (i + 1) < len(fields) {
                r.Via = fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing route spec (via): %s", line)
            }
        } else if f == "scope" {
            if (i + 1) < len(fields) {
                r.Scope = fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing route spec (scope): %s", line)
            }
        } else if f == "src" {
            if (i + 1) < len(fields) {
                r.Src = fields[i+1]
                i++
            } else {
                return nil, fmt.Errorf("Error parsing route spec (src): %s", line)
            }
        } else {
            return nil, fmt.Errorf("Error parsing route spec (unknown key): %s in %s", f, line)
        }

        i++
    }

    return r, nil
}

func readRouteFile(path string) (route *Route, err error) {
    text, err := gommons.TryReadTextFile(path, "")
    if err != nil {
        return nil, err
    }

    route, err = parseRoute(text)
    if err != nil {
        return nil, err
    }

    return route, nil
}

func showRoutes(ipv6 bool) (state *RoutesState, err error) {
    cmd := exec.Command("/sbin/ip")
    if ipv6 {
        cmd.Args = append(cmd.Args, "-6")
    }

    cmd.Args = append(cmd.Args, "route", "show")

    output, err := Execute(cmd)
    if err != nil {
        return nil, err
    }

    state = &RoutesState{}
    state.Routes = make([]*Route, 0)

    for _, line := range strings.Split(string(output), "\n") {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        route, err := parseRoute(line)
        if err != nil {
            return nil, err
        }

        state.Routes = append(state.Routes, route)
    }

    return state, nil
}

func routeMatch(l, r *Route) bool {
    return *l == *r
}

func (s *Route) buildArgs(ipv6 bool) []string {
    args := make([]string, 0)

    if ipv6 {
        args = append(args, "-6")
    }

    args = append(args, "route", "add")

    args = append(args, s.Dest)

    if s.Protocol != "" {
        args = append(args, "proto", s.Protocol)
    }
    if s.Scope != "" {
        args = append(args, "scope", s.Scope)
    }
    if s.Metric != "" {
        args = append(args, "metric", s.Metric)
    }
    if s.Via != "" {
        args = append(args, "via", s.Via)
    }
    if s.Src != "" {
        args = append(args, "src", s.Src)
    }
    if s.Device != "" {
        args = append(args, "dev", s.Device)
    }
    return args
}

func (s *Route) buildSpec(ipv6 bool) string {
    args := s.buildArgs(ipv6)
    key := strings.Join(args, " ")
    return key
}

func (s *Route) apply(ipv6 bool) (err error) {
    args := s.buildArgs(ipv6)

    cmd := exec.Command("/sbin/ip", args...)
    _, err = Execute(cmd)
    if err != nil {
        return err
    }

    return nil
}

func (s *RoutesManager) apply(state *RoutesState, basedir string) error {
    files, err := gommons.ListDirectoryNames(basedir)
    if err != nil {
        log.Printf("routes: Error listing files in dir %s: %v", basedir, err)
        return err
    }

    existingRoutes := make(map[string]*Route)

    for _, v := range state.Routes {
        key := v.buildSpec(s.Ipv6)
        existingRoutes[key] = v
    }

    for _, filename := range files {
        path := basedir + "/" + filename

        fileRoute, err := readRouteFile(path)
        if err != nil {
            return err
        }

        key := fileRoute.buildSpec(s.Ipv6)

        existingRoute := existingRoutes[key]
        if existingRoute != nil {
            delete(existingRoutes, key)

            if routeMatch(existingRoute, fileRoute) {
                //log.Printf("Configuration match: %s", filename)
                continue
            } else {
                log.Printf("Configuration mismatch: %s %s", existingRoute, fileRoute)
            }
        } else {
            log.Printf("Adding new route: %s", key)
        }

        // Configuration needs to be applied
        log.Printf("route: Applying changed configuration from disk: %s", filename)

        fileRoute.apply(s.Ipv6)
    }

    for _, v := range existingRoutes {
        // Configured in kernel, not on disk
        log.Printf("routes: Ignoring %s", v.buildSpec(s.Ipv6))
    }

    return nil
}

func (s *RoutesManager) Apply(basedir string) (err error) {
    isdir, err := gommons.IsDirectory(basedir)
    if err != nil {
        return err
    }

    if !isdir {
        log.Printf("routes: Directory not found; skipping %s", basedir)
        return nil
    }

    current, err := showRoutes(s.Ipv6)
    if err != nil {
        return err
    }

    err = s.apply(current, basedir)
    if err != nil {
        return err
    }

    return nil
}
