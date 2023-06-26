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
// Create an nftables.Interface for interacting with the "kube-proxy"
// table in the "ip" family.
nft := nftables.New(nftables.IPv4Family, "kube-proxy")

// Make sure nftables actually works here
if err := nft.Present(); err != nil {
        return fmt.Errorf("no nftables support: %v", err)
}
```

Use the `List` method on the `Interface` to check if objects exist:

```golang
chains, err := nft.List(ctx, "chains")
if err != nil {
        return fmt.Errorf("could not list chains: %v", err)
}

FIXME
```

To make changes, create a `Transaction`, add the appropriate
operations to the transaction, and then call `nft.Run` on it:

```golang
tx := nftables.NewTransaction()

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
