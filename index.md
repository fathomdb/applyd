---
title: ApplyD
layout: default
---

# ApplyD

ApplyD reads configuration from text files, and configures the OS.

It takes the ".d" configuration directory idea from Debian, and expands it to support things like iptables, ipsets, etc.

It aims to be as simple as possible.

## Overview

Create a text file (e.g. /etc/apply.d/iptables/20-allow-ssh), run applyd, and the firewall rules will be configured.

Delete the file, run applyd, and the firewall rules are removed.

Create multiple files, and applyd intelligently combines them before applying any changes.

ApplyD currently supports:

* iptables & ip6tables
* ipsets
* IPV6 Neighbor Proxies (ip -6 neigh)
* Virtual IPs (ip addr add)

Obviously it's very networking focused.  That's partially because that's what we needed when building our OpenStack implementation, and partially because other systems already have ".d" support. 

### Can't I do this using scripts?

Yes, but:

*   Scripts can't easily remove configuration.

    > It's tricky to have one iptables script do both add and remove.  You can do it, but you'd probably be recreating applyd!

*   It's tricky to combine scripts.

    > With iptables, you want to apply the configuration atomically, so you should use iptables-restore instead of multiple commands.


### Can't I do this using Chef / Puppet / Ansible / Salt / ...?

Yes, but:

*   It's more complicated.
*   If you do, it's all or nothing; you can't mix multiple management tools.

    > Suppose you have a program that manages its own firewall rules; it'll 'battle' with configuration management tools.

*   Configuration tools should write applyd files.

    > We hope that configuration tools will write applyd files, so that multiple tools can get coexist.

    > Hopefully also, this approach will eventually become part of standard Linux installs.  The .d approach is already widely accepted, it just doesn't cover all systems yet (iptables...).

    > ApplyD is a bridge, until distros support .d configuration for iptables etc. 

