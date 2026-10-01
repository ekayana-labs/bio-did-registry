# Contributing

Thanks for your interest in the did:bio registry program!

## Development setup

You need the Rust version pinned in [rust-toolchain.toml](rust-toolchain.toml)
and the [Solana CLI](https://solana.com/docs/intro/installation) v3.1 or
later, which provides `cargo build-sbf`.

```console
cargo build-sbf --manifest-path program/Cargo.toml
cargo build-sbf --manifest-path program/tests/fixtures/cpi-caller/Cargo.toml
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

The integration tests run under [LiteSVM](https://github.com/LiteSVM/litesvm),
so no local validator is needed. `cargo test --test compute_units -- --nocapture`
prints the per-instruction compute-unit report.

## Rules

- The wire format is frozen. Deployed clients and the
  [`did-bio-core`](https://github.com/ekayana-labs/did-bio-core) resolver
  consume the instruction, account and event discriminators, the borsh
  account layout, the PDA seeds and the domain error codes `6000..=6018`. A
  change to any of them is a breaking protocol change and needs an issue
  and a migration plan first.
- The program never allocates. It is `no_std` with `no_allocator!`, and
  handlers edit account data in place. A PR that introduces heap allocation
  will be asked to restructure.
- Every behavior change needs a test that covers the positive and the
  negative path. Error codes are asserted by number.
- Compute units are watched. The `compute_units` test enforces a
  per-instruction ceiling. If your change moves costs materially, include
  the numbers before and after in the PR description.

## Commit messages

Write a short, capitalized, imperative subject with no trailing period,
such as `Add service instructions` or `Fix rent refund on shrink`. Use a
`ci:`, `docs:`, `deps:` or `chore:` prefix only for mechanical changes.
Explain why in the body when the diff does not make it obvious.

## Pull requests

- Keep each PR to one logical change.
- CI must pass. It runs fmt, clippy, build-sbf and the tests.
- For anything touching authorization, rent settlement, or the account
  layout, describe the invariant you preserved and how the tests prove it.
