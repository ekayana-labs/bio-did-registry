# Contributing

Thanks for your interest in the did:bio registry program!

## Development setup

You need Rust (the version pinned in [rust-toolchain.toml](rust-toolchain.toml))
and the [Solana CLI](https://solana.com/docs/intro/installation) v3.1+
(for `cargo build-sbf`).

```console
cargo build-sbf --manifest-path program/Cargo.toml
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

The integration tests run under [LiteSVM](https://github.com/LiteSVM/litesvm);
no local validator is needed. `cargo test --test compute_units -- --nocapture`
prints the per-instruction compute-unit report.

## Rules of the road

- **The wire format is frozen.** Instruction/account/event discriminators,
  the borsh account layout, PDA seeds, and the domain error codes
  (6000..6014) are consumed by deployed clients and the
  [`did-bio-core`](https://github.com/ekayana-labs/did-bio-core) resolver.
  Changes to any of them are breaking protocol changes and need an issue and
  a migration story first.
- **Zero allocation is a feature.** The program is `no_std` with
  `no_allocator!`; handlers edit account data in place. PRs that introduce
  heap allocation will be asked to restructure.
- **Every behavior change needs a test.** Positive and negative paths; error
  codes are asserted by number.
- **Watch compute units.** The `compute_units` test enforces a per-instruction
  ceiling. If your change moves costs materially, include before/after
  numbers in the PR description.

## Commit messages

Follow the style used in this repository's history:

- A short, capitalized, imperative subject line, no trailing period:
  `Add service instructions`, `Fix rent refund on shrink`.
- Use a scoped prefix only for mechanical changes: `ci:`, `docs:`,
  `deps:`, `chore:`.
- Explain *why* in the body when the diff doesn't make it obvious.

## Pull requests

- Keep PRs focused; one logical change per PR.
- CI (fmt, clippy, build-sbf, tests) must pass.
- For anything touching authorization, rent settlement, or the account
  layout, describe the invariant you preserved and how the tests prove it.
