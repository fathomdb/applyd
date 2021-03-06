package main

import (
    "flag"
    "github.com/fathomdb/applyd"
    "log"
    "math/rand"
    "os"
    "time"
)

func main() {
    rand.Seed(time.Now().UTC().UnixNano())

    flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

    err := flags.Parse(os.Args[1:])
    if err != nil {
        log.Panicf("Error parsing flags %v", err)
    }

    runtime, err := applyd.NewRuntime()
    if err != nil {
        log.Panicf("Error initializing %v", err)
    }

    //	packages, err := runtime.Packages.List()
    //	if err != nil {
    //		log.Panicf("Error listing packages %v", err)
    //	}

    //	for _, p := range packages {
    //		fmt.Printf("Package %s\n", p.Name)
    //	}

    //	packages, err = runtime.Packages.Install("ipset")
    //	if err != nil {
    //		log.Panicf("Error installing package %v", err)
    //	}

    //	err = runtime.Firewall.Save("/tmp/state")
    //	if err != nil {
    //		log.Panicf("Error saving firewall state %v", err)
    //	}

    err = runtime.Firewall.Apply("/etc/apply.d")
    if err != nil {
        log.Panicf("Error applying state %v", err)
    }

    err = runtime.IpNeighbors.Apply("/etc/apply.d/ip6neigh")
    if err != nil {
        log.Panicf("Error applying state %v", err)
    }

    err = runtime.Tunnels.Apply("/etc/apply.d/tunnel")
    if err != nil {
        log.Panicf("Error applying tunnels %v", err)
    }

    err = runtime.Vips.Apply("/etc/apply.d/vips")
    if err != nil {
        log.Panicf("Error applying vips %v", err)
    }

    err = runtime.Routes4.Apply("/etc/apply.d/route4")
    if err != nil {
        log.Panicf("Error applying ipv4 routes %v", err)
    }

    err = runtime.Routes6.Apply("/etc/apply.d/route6")
    if err != nil {
        log.Panicf("Error applying ipv6 routes %v", err)
    }

}
