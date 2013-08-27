---
title: ApplyD - iptables & ip6tables
layout: default
---

# ApplyD: iptables & ip6tables

ApplyD can configure iptables & ip6tables.  The syntax of each file is the same as the syntax created by iptables-save.

If you're in doubt as to the correct syntax, add the rule using the command line, run iptables-save, and grab the relevant bit.

## Example: Allow SSH (port 22)

## Example: Allow Ping / ICMP traffic


```bash
/etc/apply.d/iptables/20-allow-icmp

*filter
-A INPUT -p icmp -j ACCEPT
COMMIT
```

/etc/apply.d/ip6tables/20-allow-icmp

```bash
*filter
-A INPUT -p icmpv6 -j ACCEPT
COMMIT
```


