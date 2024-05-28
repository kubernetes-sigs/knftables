# Porting iptables-based components to nftables

Although it's possible to port an iptables-based component to nftables
in a mostly "dumb" way that just translates the iptables chains to
nftables, this isn't really encouraged, and knftables isn't designed
to necessarily make that easy.

(There is no particular organization to this document; it's basically
a braindump.)

## NFTables tables are private

In iptables, everyone has to share the same `filter`, `nat`, `raw`,
and `mangle` tables, and has to figure out how to not interfere with
each other.

In nftables, everyone is expected to create their own table, and _not
touch_ anyone else's tables. You use the `priority` levels of base
chains to control what happens before and after what.

## Sets and Maps

NFTables sets and maps are awesome, and you should try to use them.

IPTables style:

```
-A KUBE-SERVICES -m comment --comment "ns1/svc1:p80 cluster IP" -m tcp -p tcp -d 172.30.0.41 --dport 80 -j KUBE-SVC-XPGD46QRK7WJZT7O
-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 cluster IP" -m tcp -p tcp -d 172.30.0.42 --dport 80 -j KUBE-SVC-GNZBNJ2PO5MGZ6GT
-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 external IP" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
-A KUBE-SERVICES -m comment --comment "ns2/svc2:p80 loadbalancer IP" -m tcp -p tcp -d 1.2.3.4 --dport 80 -j KUBE-EXT-GNZBNJ2PO5MGZ6GT
-A KUBE-SERVICES -m comment --comment "ns3/svc3:p80 cluster IP" -m tcp -p tcp -d 172.30.0.43 --dport 80 -j KUBE-SVC-X27LE4BHSL4DOUIK
-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 cluster IP" -m tcp -p tcp -d 172.30.0.44 --dport 80 -j KUBE-SVC-4SW47YFZTEDKD3PK
-A KUBE-SERVICES -m comment --comment "ns4/svc4:p80 external IP" -m tcp -p tcp -d 192.168.99.33 --dport 80 -j KUBE-EXT-4SW47YFZTEDKD3PK
-A KUBE-SERVICES -m comment --comment "ns5/svc5:p80 cluster IP" -m tcp -p tcp -d 172.30.0.45 --dport 80 -j KUBE-SVC-NUKIZ6OKUXPJNT4C
-A KUBE-SERVICES -m comment --comment "ns5/svc5:p80 loadbalancer IP" -m tcp -p tcp -d 5.6.7.8 --dport 80 -j KUBE-FW-NUKIZ6OKUXPJNT4C
```

NFTables style:

```
add chain ip kube-proxy services
add rule ip kube-proxy services ip daddr . meta l4proto . th dport vmap @service-ips

add element ip kube-proxy service-ips { 172.30.0.41 . tcp . 80 : goto service-ULMVA6XW-ns1/svc1/tcp/p80 }
add element ip kube-proxy service-ips { 172.30.0.42 . tcp . 80 : goto service-42NFTM6N-ns2/svc2/tcp/p80 }
add element ip kube-proxy service-ips { 192.168.99.22 . tcp . 80 : goto external-42NFTM6N-ns2/svc2/tcp/p80 }
add element ip kube-proxy service-ips { 1.2.3.4 . tcp . 80 : goto external-42NFTM6N-ns2/svc2/tcp/p80 }
add element ip kube-proxy service-ips { 172.30.0.43 . tcp . 80 : goto service-4AT6LBPK-ns3/svc3/tcp/p80 }
add element ip kube-proxy service-ips { 172.30.0.44 . tcp . 80 : goto service-LAUZTJTB-ns4/svc4/tcp/p80 }
add element ip kube-proxy service-ips { 192.168.99.33 . tcp . 80 : goto external-LAUZTJTB-ns4/svc4/tcp/p80 }
add element ip kube-proxy service-ips { 172.30.0.45 . tcp . 80 : goto service-HVFWP5L3-ns5/svc5/tcp/p80 }
add element ip kube-proxy service-ips { 5.6.7.8 . tcp . 80 : goto external-HVFWP5L3-ns5/svc5/tcp/p80 }
```

The nftables ruleset is O(1)-ish; there is a single rule, regardless
of how many services you have. The iptables ruleset is O(n); the more
services you have, the more rules netfilter has to run against each
packet.

## Static vs dynamic rule sets

Related to the above, iptables-based components tend to need to
frequently add and delete individual rules. In nftables, it is more
common to have a static set of rules (e.g., the single map lookup rule
above), and have dynamically modified sets and maps.

In iptables, you can delete a rule by using the same syntax you used
to create it. In nftables, this isn't possible; if you want to delete
a rule, you need to know the current index or the static handle of the
rule. This makes dynamically altering rules slightly more complicated
(and, at the time of writing, knftables doesn't provide any way to
learn the handle of a rule at the time the rule is created).

As a result of the above (and the fact that you can safely assume that
other components aren't adding rules to your tables), in idiomatic
knftables usage, when you aren't sure that the current state of the
chain is correct, it tends to be more common to flush-and-recreate the
chain rather than checking whether individual rules exist in it and are
correct.

## Use of comments

In iptables, comments only exist on rules. In nftables, you can add
comments to:

  - rules
  - set/map elements
  - chains
  - sets
  - maps
  - tables

When porting kube-proxy, we found that in many places where kube-proxy
had per-rule comments, we really only needed per-chain comments, which
explained all of the rules in the chain.

(Additionally, we ended up getting rid of a lot of comments just
because we use much longer and more-self-documenting chain names in
the nftables kube-proxy backend, as seen above. (The maximum length of
an nftables chain name is 256, as compared to iptables's 32.))

## The `inet`, `ip`, and `ip6` tables

For dual-stack rulesets, nftables provides two options:

  - Put IPv4 rules in an `ip`-family table and IPv6 rules in an `ip6`-family table.
  - Put all rules in an `inet`-family table.

For kube-proxy, the architecture of kube-proxy meant that the split
`ip`/`ip6` option made much more sense. But the split option often
ends up making sense for other components too, because you can't have
sets/maps that hold/match both IPv4 and IPv6 addresses. If you need to
have rules that match particular IPs against a set or map, then you
need to have per-IP-family sets/map regardless of whether the rules
are in `ip`/`ip6` or `inet`.
