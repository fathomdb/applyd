---
title: ApplyD - iptables & ip6tables
layout: default
---

# ApplyD: iptables & ip6tables

ApplyD can configure iptables & ip6tables.  The syntax of each file is the same as the syntax created by iptables-save.

If you're in doubt as to the correct syntax, add the rule using the command line, run iptables-save, and grab the relevant bit.

## Example: Allow SSH (port 22)


##### /etc/apply.d/iptables/20-allow-ssh
```bash
*filter
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
```

##### /etc/apply.d/ip6tables/20-allow-ssh

```bash
*filter
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
```

> The `*filter ... COMMIT` is iptables-save syntax.  `*<type>` specifies the table (filter and nat are the two commonly used ones).  `COMMIT` ends the table block.

> Yes, it is sort of annoying that IPV4 & IPV6 must be configured separately.  We're mirroring the iptables & ip6tables commands here.

## Example: Allow Ping / ICMP traffic

##### /etc/apply.d/iptables/20-allow-icmp
```bash
*filter
-A INPUT -p icmp -j ACCEPT
COMMIT
```

##### /etc/apply.d/ip6tables/20-allow-icmp

```bash
*filter
-A INPUT -p icmpv6 -j ACCEPT
COMMIT
```

## Example: NAT a bridge interface

##### /etc/apply.d/iptables/10-nat
```bash
*nat
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT
*filter
-A FORWARD -i eth0 -o br0 -j ACCEPT
-A FORWARD -i br0 -o eth0 -j ACCEPT
-A INPUT -m state --state ESTABLISHED -j ACCEPT
COMMIT
```

> Multiples files are combined in order, sorted by name.  Where the order matters use the `NN-` prefix to control the ordering.

