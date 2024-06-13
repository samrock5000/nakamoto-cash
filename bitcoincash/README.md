[![pipeline status](https://gitlab.com/rust-bitcoincash/rust-bitcoincash/badges/master/pipeline.svg)](https://gitlab.com/rust-bitcoincash/rust-bitcoincash/commits/master)
[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

# Rust Bitcoin Cash Library

A minimal fork of [Rust Bitcoin
Library](https://github.com/rust-bitcoin/rust-bitcoin) to support Bitcoin Cash.

[Documentation](https://rust-bitcoincash.gitlab.io/rust-bitcoincash/bitcoincash)

Supports (or should support)

* De/serialization of Bitcoin protocol network messages
* De/serialization of blocks and transactions
* Script de/serialization
* Private keys and address creation, de/serialization and validation (including full BIP32 support)
* PSBT v0 de/serialization and all but the Input Finalizer role. Use [rust-miniscript](https://docs.rs/miniscript/latest/miniscript/psbt/index.html) to finalize.

# Changes from upstream

* Added testnet4, scalenet and chipnet support
* Increased network message size limit (allow for 256MB blocks)
* Partial support for CashTokens (Sighash updates missing)
* New opcodes

It is recommended to always use [cargo-crev](https://github.com/crev-dev/cargo-crev)
to verify the trustworthiness of each of your dependencies, including this one.

## Known limitations

### Consensus

This library **should not** be used for consensus code (i.e. fully validating
blockchain data). It technically supports doing this, but doing so is very
ill-advised because there are many deviations, known and unknown, between
this library and the Bitcoin Cash node implementations. In a consensus
based cryptocurrency such as Bitcoin it is critical that all parties are
using the same rules to validate data.

Patches to fix specific consensus incompatibilities are welcome.

### Support for 16-bit pointer sizes

16-bit pointer sizes are not supported and we can't promise they will be.
If you care about them please let us know, so we can know how large the interest
is and possibly decide to support them.

## Documentation

Currently can be found on [the projects gitlab
page](https://rust-bitcoincash.gitlab.io/rust-bitcoincash/bitcoincash).
Patches to add usage examples and to expand on existing docs would be extremely
appreciated.

## Contributing

Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before MRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[rustbitcoincash](http://t.me/rustbitcoincash) on Telegram.

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features (minus
`no-std`) on **Rust 1.41.1** or **Rust 1.47** with `no-std`.

## Installing Rust

Rust can be installed using your package manager of choice or
[rustup.rs](https://rustup.rs). The former way is considered more secure since
it typically doesn't involve trust in the CA system. But you should be aware
that the version of Rust shipped by your distribution might be out of date.
Generally this isn't a problem for `rust-bitcoin` since we support much older
versions than the current stable one (see MSRV section).

## Building

The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone https://gitlab.com/rust-bitcoincash/rust-bitcoincash.git
cd rust-bitcoincash
cargo build
```

You can run tests with:

```
cargo test
```

Please refer to the [`cargo` documentation](https://rust-bitcoincash.gitlab.io/rust-bitcoincash/bitcoincash) for more detailed instructions.

### Building the docs

We build docs with the nightly toolchain, you may wish to use the following
shell alias to check your documentation changes build correctly.

```
alias build-docs='RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --features="$FEATURES" -- -D rustdoc::broken-intra-doc-links'
```

### Running benchmarks

We use a custom Rust compiler configuration conditional to guard the bench mark code. To run the
bench marks use: `RUSTFLAGS='--cfg=bench' cargo +nightly bench`.

## Pull Requests

Every PR needs at least two reviews to get merged. During the review phase
maintainers and contributors are likely to leave comments and request changes.
Please try to address them, otherwise your PR might get closed without merging
after a longer time of inactivity. If your PR isn't ready for review yet please
mark it by prefixing the title with `WIP: `.

### CI Pipeline

The CI pipeline requires approval before being run on each MR.

In order to speed up the review process the CI pipeline can be run locally using
[act](https://github.com/nektos/act). The `fuzz` and `Cross` jobs will be
skipped when using `act` due to caching being unsupported at this time. We do
not *actively* support `act` but will merge PRs fixing `act` issues.

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. If you do not
already have locally configured githooks you can use the ones in this repository by running, in the
root directory of the repository:
```
git config --local core.hooksPath githooks/
```

Alternatively add symlinks in your `.git/hooks` directory to any of the githooks we provide.

## Policy on Altcoins/Altchains

Patches which add support for non-BitcoinCash cryptocurrencies by adding constants
to existing enums (e.g. to set the network message magic-byte sequence) are
welcome. Anything more involved will be considered on a case-by-case basis,
as the altcoin landscape includes projects which [frequently appear and
disappear, and are poorly designed anyway](https://download.wpsoftware.net/bitcoin/alts.pdf)
and keeping the codebase maintainable is a large priority.

In general, things that improve cross-chain compatibility (e.g. support for
cross-chain atomic swaps) are more likely to be accepted than things which
support only a single blockchain.


## Release Notes

See [CHANGELOG.md](CHANGELOG.md).


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0
Universal license](LICENSE). We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX
IDs](https://spdx.dev/ids/).
