# did:bio Registry Program

The Solana verifiable data registry backing the
[`did:bio`](https://github.com/ekayana-labs/did-bio-spec) W3C DID method -
decentralized identifiers for researchers, datasets, and research
infrastructure.

| Information | Account Address |
| --- | --- |
| did:bio Registry Program | `H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6` |

Currently live on **devnet**.

## Overview

Every Ed25519 keypair *is* a DID: `did:bio:devnet:<base58-pubkey>` resolves
to a deterministic generative DID document at zero cost. Writing the
on-chain account (PDA `["bio-did", subject]`, 124 bytes initially) unlocks:

- **Key rotation** - add/remove verification methods; the five W3C DID
  verification relationships (authentication, assertionMethod, keyAgreement,
  capabilityInvocation, capabilityDelegation) are stored as bitflags
- **Post quantum keys** - ML-DSA-87 (FIPS 204) verification methods for
  long-lived off-chain assertions
- **Services** - e.g. `BioMetadata -> ipfs://<cid>` anchoring research
  metadata, `DataverseRepository -> doi.org/...`
- **Controllers** - link dataset DIDs to researcher/organization DIDs
- **Permanent deactivation** - a rent-refunding tombstone; a deactivated DID
  can never resurrect as its generative document

All mutations require an Ed25519 signature from a verification method
carrying the `capabilityInvocation` relationship. `initialize` is
permissionless, so a platform can sponsor account creation while the subject
keeps sole control: the created state is exactly the generative document.

The program is built with [Pinocchio](https://github.com/anza-xyz/pinocchio):
`no_std`, allocation-free (`no_allocator!`), with account data edited in
place - a document holding sixteen 2.5 KB post-quantum keys costs the same
~3-6k compute units per edit as a minimal one. Accounts are exact-size at
all times: every instruction reallocates to the minimal serialized layout
and settles the balance to exactly the rent-exempt minimum (growth funded by
the payer, shrinkage refunded to the payer).

## Wire format

The wire format is frozen and pinned by golden vectors in the test suite and
by the [`did-bio-core`](https://github.com/ekayana-labs/did-bio-core)
resolver crate:

- instruction discriminators: `sha256("global:<name>")[..8]`
- account discriminator: `sha256("account:DidAccount")[..8]`
- events (`sha256("event:<Name>")[..8]` + borsh) via `sol_log_data`
- domain errors as custom program error codes `6000..=6014`

See the [did:bio method specification](https://github.com/ekayana-labs/did-bio-spec)
for the account layout, resolution algorithm, and security analysis.

## Security

This program has **not yet received an external audit**. See
[SECURITY.md](SECURITY.md) for how to report vulnerabilities.

Core invariants enforced on-chain:

- only `capabilityInvocation` Ed25519 keys may mutate a document
- the last update authority can never be removed or de-flagged
- `PROTECTED` verification methods only change under their own key
- a sponsor who pays for `initialize` gains no control over the DID
- deactivation is permanent (tombstone, never account closure)

## Building and Verifying

```console
cargo build-sbf --manifest-path program/Cargo.toml
```

The deployed program can be verified against this source with
[solana-verify](https://solana.com/developers/guides/advanced/verified-builds):

```console
solana-verify build --library-name did_bio_registry
solana-verify get-program-hash -ud H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6
```

## Testing

Integration tests run under [LiteSVM](https://github.com/LiteSVM/litesvm). Instructions are hand-encoded and accounts are decoded by an independent 
parser, so the tests pin the wire format itself:

```console
cargo build-sbf --manifest-path program/Cargo.toml
cargo test
cargo test --test compute_units -- --nocapture   # per-instruction CU report
```

## Compute Units

Baselines measured with the `compute_units` test (rounded to hundreds;
`initialize` varies with the PDA bump search). The binary is ~75 KB and the
per edit cost is independent of document size.

| Instruction | Estimated Cost |
| --- | --- |
| `initialize` | 3600+ |
| `add_verification_method` (Ed25519) | 4900 |
| `add_verification_method` (ML-DSA-87, 2.5 KB key) | 4800 |
| `remove_verification_method` | 3500 |
| `set_verification_method_flags` | 3100 |
| `add_service` | 5900 |
| `remove_service` | 3400 |
| `set_controllers` (2 native + 2 external) | 5700 |
| `deactivate` | 2900 |

## License

[MIT](LICENSE)
