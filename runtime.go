package applyd

import ()

type Runtime struct {
    Packages    *PackageManager
    Firewall    *FirewallManager
    IpNeighbors *IpNeighborProxyManager
    Vips        *VipsManager
}

func NewRuntime() (*Runtime, error) {
    runtime := &Runtime{}

    runtime.Packages = NewPackageManager(runtime)
    runtime.Firewall = NewFirewallManager(runtime)
    runtime.IpNeighbors = NewIpNeighborProxyManager(runtime)
    runtime.Vips = NewVipsManager(runtime)

    return runtime, nil
}
