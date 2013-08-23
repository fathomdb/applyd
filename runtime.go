package applyd

import ()

type Runtime struct {
    Packages    *PackageManager
    Firewall    *FirewallManager
    IpNeighbors *IpNeighborProxyManager
}

func NewRuntime() (*Runtime, error) {
    runtime := &Runtime{}

    runtime.Packages = NewPackageManager(runtime)
    runtime.Firewall = NewFirewallManager(runtime)
    runtime.IpNeighbors = NewIpNeighborProxyManager(runtime)

    return runtime, nil
}
