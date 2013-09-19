package applyd

import ()

type Runtime struct {
    Packages    *PackageManager
    Firewall    *FirewallManager
    IpNeighbors *IpNeighborProxyManager
    Vips        *VipsManager
    Tunnels     *TunnelsManager
}

func NewRuntime() (*Runtime, error) {
    runtime := &Runtime{}

    runtime.Packages = NewPackageManager(runtime)
    runtime.Firewall = NewFirewallManager(runtime)
    runtime.IpNeighbors = NewIpNeighborProxyManager(runtime)
    runtime.Vips = NewVipsManager(runtime)
    runtime.Tunnels = NewTunnelsManager(runtime)

    return runtime, nil
}
