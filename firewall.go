package applyd

import ()

type FirewallManager struct {
    runtime *Runtime

    ipsets    *IpsetManager
    ip4tables *IptablesManager
    ip6tables *IptablesManager
}

func NewFirewallManager(runtime *Runtime) *FirewallManager {
    p := &FirewallManager{}
    p.runtime = runtime

    p.ipsets = NewIpsetManager(p)
    p.ip4tables = NewIptablesManager(p, false)
    p.ip6tables = NewIptablesManager(p, true)

    return p
}

func (s *FirewallManager) Save(basedir string) (err error) {
    err = s.ipsets.Save(basedir + "/ipset")
    if err != nil {
        return err
    }

    err = s.ip4tables.Save(basedir + "/iptables")
    if err != nil {
        return err
    }

    err = s.ip6tables.Save(basedir + "/ip6tables")
    if err != nil {
        return err
    }

    return nil
}

func (s *FirewallManager) Apply(basedir string) (err error) {
    err = s.ipsets.Apply(basedir + "/ipset")
    if err != nil {
        return err
    }

    err = s.ip4tables.Apply(basedir + "/iptables")
    if err != nil {
        return err
    }

    err = s.ip6tables.Apply(basedir + "/ip6tables")
    if err != nil {
        return err
    }

    return nil
}
