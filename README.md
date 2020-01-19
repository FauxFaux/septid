## septid

[![Build status](https://api.travis-ci.org/FauxFaux/septid.png)](https://travis-ci.org/FauxFaux/septid)
[![](https://img.shields.io/crates/v/septid.svg)](https://crates.io/crates/septid)

`septid` contains an implementation of the [`spiped`](https://www.tarsnap.com/spiped.html) protocol.

`spiped` can be used to make secure connections across the network,
without the complexities of a full TLS ("https") implementation.

`septid` currently contains a *write-only* client, `SPipe`.

For usage, please consult the [documentation on docs.rs](https://docs.rs/septid),
or the [CLI example](examples/write-only.rs).

## MSRV

Rust 1.39 (`async/await`) is supported, and checked by Travis.

This is required by `zeroize`, but not (yet) by us directly.

Updating this is a minor semver bump.

## License

`MIT or Apache-2.0`
