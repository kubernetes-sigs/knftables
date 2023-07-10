# golang nftables library

This is a library for using nftables from Go.

It is not intended to support arbitrary use cases, but instead
specifically focuses on supporing Kubernetes components which are
using nftables in the way that nftables is supposed to be used (as
opposed to using nftables in a naively-translated-from-iptables way,
or using nftables to do totally valid things that aren't the sorts of
things Kubernetes components are likely to need to do).

It is still under development and is not API stable.

## Usage

Create an `Interface` object to manage operations on a single nftables
table:

```golang
nft := nftables.New()

// Make sure nftables actually works here
if err := nft.Present(); err != nil {
        return fmt.Errorf("no nftables support: %v", err)
}
```

Use the `List` method on the `Interface` to check if objects exist:

```golang
chains, err := nft.List(ctx, nftables.IPv4Family, "my-table", "chains")
if err != nil {
        return fmt.Errorf("could not list chains: %v", err)
}

FIXME
```

To make changes, create a `Transaction`, add the appropriate
operations to the transaction, and then call `nft.Run` on it:

```golang
tx := nftables.NewTransaction(nftables.IPv4Family, "my-table")

tx.Add(&nftables.Chain{
        Name:    "mychain",
        Comment: nftables.Optional("this is my chain"),
})
tx.Flush(&nftables.Chain{
        Name: "mychain",
})

tx.AddRule("mychain",
        "ip daddr", destIP,
        "jump", destChain,
)
```

NOTE: I may move the family and table name specification from the
`Transaction` to the `Interface`, such that a given
`nftables.Interface` _only_ works with a single table.

## `nftables.Transaction` operations

`nftables.Transaction` operations correspond to the top-level commands
in the `nft` binary. Currently-supported operations are:

- `tx.Add()`: adds an object, as with `nft add`
- `tx.Flush()`: flushes the contents of a table/chain/set/map, as with `nft flush`
- `tx.Delete()`: deletes an object, as with `nft delete`

There is also currently one helper function:

- `tx.AddRule()`: wrapper around `tx.Add(&nftables.Rule{...})` that
  makes it easy to assemble the text of a rule from multiple pieces.

## Objects

The `Transaction` methods take arguments of type `nftables.Object`.
The currently-supported objects are:

- `Table`
- `Chain`
- `Rule`
- `Set`
- `Map`
- `Element`

`Table` has a `Name` field of type `*TableName` and every other object
has a `Table` field of type `*TableName`, for specifying the family
and table name, but you do not normally need to fill these in, because
they get filled in automatically with the values from the `Interface`.

Optional fields in objects can be filled in with the help of the
`Optional()` function, which just returns a pointer to its
argument.

The `Join()` and `Split()` helper functions can be used with set and
map keys and values, to convert between multiple values specified
separately, and a single string with the values separated by dots.

## Missing APIs

Various top-level object types are not yet supported (notably the
"stateful objects" like `counter`).

There needs to be a way to list the elements of a set/map, and/or to
check whether a set/map contains a particular element.

Most IPTables libraries would likewise have APIs to list the rules in
a chain / check whether a chain contains a rule / add a rule to a
chain only if it's not already there. But that does not seem as useful
in nftables (or at least "in nftables as used by Kubernetes-ish
components that aren't just blindly copying over old iptables APIs")
because chains tend to have static rules and dynamic sets/maps, rather
than having dynamic rules. If you aren't sure if a chain has the
correct rules, you can just `Flush` it and recreate all of the rules.

Although the API supports `tx.Delete(&nftables.Rule{...})`, it's not
actually possible to use it (without getting information from outside
sources), because you need to know the `Handle` of the rule in order
to delete it, but we provide no way to find that out. In theory if we
had a "list rule(s)" operation you could use that to find it, or if we
used the `--handle` (`-a`) and `--echo` (`-e`) flags to `nft` when
doing an `add rule`, we could learn the handle then, and return that
to the caller as part of running the transaction.

But again, in my experience chains tend to have static rules, so you
don't normally want to do `tx.Delete(&nftables.Rule{...})` anyway.
(You _do_ need to be able to delete individual set/map elements, but
you don't need to use handles for that; deleting a set/map element
uses the same syntax as adding one.)

Likewise, we don't currently support the `insert rule` and `replace
rule` commands. Syntactically, this would be easy, but semantically it
would be awkward for the same reason as rule deletion is (needing to
know handles), and it is likewise of uncertain usefulness.

# Design Notes

The library works by invoking the `nft` binary, mostly not using the
`--json` mode.

Although it might seem like we ought to use either the low-level
(netlink) interface, or at least the JSON interface, that doesn't seem
like a good idea in practice. The documented syntax of nftables rules
and set/map elements is implemented by the higher-level APIs, so if we
used the lower-level APIs (or the JSON API, which wraps the
lower-level APIs), then the official nftables documentation would be
mostly useless to people using this library. (You would essentially be
forced to do `nft add rule ...; nft -j list chain ...` to figure out
the JSON syntax for the rules you wanted so you could then write it in
the form the library needed.)

Using the non-JSON syntax has its own problems, and means that it is
basically impossible for us to reliably parse rules, which means that
the missing "does chain X contain rule Y?" and "what is the handle for
rule Z?" APIs mentioned above are likely to stay missing.

The fact that the API uses functions and objects (e.g.
`tx.Add(&nftables.Chain{...})`) rather than just specifying everything
as textual input to `nft` (e.g. `tx.Exec("add chain ...")`) is mostly
just because it's _much_ easier to have a fake implementation for unit
tests this way.

The `tx.AddRule()` API is 100% just copied from the `LineBuffer` used
by the kube-proxy iptables backend. I considered having a
`tx.AddElement()` helper too, but that doesn't work as well, because
elements aren't "flat" like rules are, so you can't just squish
multiple `string` and `[]string` elements together.
