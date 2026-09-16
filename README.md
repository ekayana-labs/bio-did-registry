# did:bio Registry Program

[![CI](https://github.com/ekayana-labs/bio-did-registry/actions/workflows/main.yml/badge.svg)](https://github.com/ekayana-labs/bio-did-registry/actions/workflows/main.yml)
[![verified build](https://github.com/ekayana-labs/bio-did-registry/actions/workflows/verified-build.yml/badge.svg)](https://github.com/ekayana-labs/bio-did-registry/actions/workflows/verified-build.yml)
[![crates.io](https://img.shields.io/crates/v/bio-did-registry.svg)](https://crates.io/crates/bio-did-registry)
[![docs.rs](https://img.shields.io/docsrs/bio-did-registry)](https://docs.rs/bio-did-registry)
[![MSRV](https://img.shields.io/crates/msrv/bio-did-registry)](Cargo.toml)
[![license](https://img.shields.io/crates/l/bio-did-registry)](LICENSE)
[![devnet](https://img.shields.io/badge/solana%20devnet-H1gn...3Xxy6-0d9488)](https://explorer.solana.com/address/H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6?cluster=devnet)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ekayana-labs/bio-did-registry/badge)](https://scorecard.dev/viewer/?uri=github.com/ekayana-labs/bio-did-registry)

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
  long-lived off-chain assertions, uploaded in chunks through a key buffer
- **Services** - e.g. `BioMetadata -> ipfs://<cid>` anchoring research
  metadata, `DataverseRepository -> doi.org/...`
- **Controllers** - link dataset DIDs to researcher/organization DIDs
- **Permanent deactivation** - a rent-refunding tombstone; a deactivated DID
  can never resurrect as its generative document

All mutations require an Ed25519 signature from a verification method
carrying the `capabilityInvocation` relationship. `initialize` is
permissionless, so a platform can sponsor account creation while the subject
keeps sole control: the created state is exactly the generative document.
The subject has to be a key: an address off the Ed25519 curve is refused
(`InvalidArgument`), since nothing could ever sign for the document it
would name.

A DID does not have to be a key. `initialize_owned(nonce)` derives the
subject from the signing authority (`["bio-did-owned", authority, nonce]`,
an off-curve program address) and makes that authority's key the document's
first verification method, so a wallet names a dataset, paper or claim it
owns, pays for and controls with one signature. See [Owned DIDs](#owned-dids).

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
- account discriminators: `sha256("account:DidAccount")[..8]` and
  `sha256("account:KeyBuffer")[..8]`
- events (`sha256("event:<Name>")[..8]` + borsh) via `sol_log_data`
- domain errors as custom program error codes `6000..=6017`
- instruction arguments are exact: bytes past the last field are rejected
  as `InvalidInstructionData`, the way borsh's `try_from_slice` rejects them

See the [did:bio method specification](https://github.com/ekayana-labs/did-bio-spec)
for the account layout, resolution algorithm, and security analysis.

## Large keys

An ML-DSA-87 public key is 2592 bytes and a Solana transaction is at most
1232, so post quantum keys cannot travel in `add_verification_method`. They
go through a staging account instead:

1. `create_key_buffer(fragment, type, flags, key_len)` opens a `KeyBuffer`
   PDA at `["bio-did-key", did_account, authority]`, funded by the payer and
   bound to the signing authority. Every rule that does not need the key
   bytes is checked here, so a doomed upload fails before any chunk is sent.
2. `write_key_buffer(offset, chunk)` appends chunks in order. Chunks of 900
   bytes keep each transaction under the limit; an ML-DSA-87 key takes three.
3. `add_verification_method_from_buffer()` re-checks every rule against the
   DID's current state, appends the method, closes the buffer, and refunds
   its rent to the payer.
4. `close_key_buffer()` abandons an upload and refunds its rent.

Only the bound authority can write, finish, or close a buffer, a buffer
lands only in the DID it was opened for, and one buffer per authority and
DID exists at a time. The `bio-did-resolver` command line hides the sequence
behind a single `add-key` invocation.

## Owned DIDs

Research assets need identifiers of their own, but a fresh keypair per
asset means someone has to keep that key. An owned DID has no key:

```text
subject     = find_program_address(["bio-did-owned", authority, nonce_le], PROGRAM_ID)
did_account = find_program_address(["bio-did", subject], PROGRAM_ID)
```

`initialize_owned(nonce)` takes `[payer, authority, did_account,
system_program]`, requires the authority's signature, and writes the same
124-byte initial document as `initialize` with the authority's key as the
protected `#default` method. From then on the DID behaves like any other:
services, controllers, key rotation, post-quantum keys, deactivation. The
subject is off the curve, so no generative document exists for it and it
resolves only through the registry (`notFound` until the account is
created, `deactivated` forever after a tombstone). Because the authority
must sign, nobody can register an owned DID in another wallet's name, and
the same nonce under two authorities yields two unrelated DIDs.

## Using the crate

The program is published to [crates.io](https://crates.io/crates/bio-did-registry)
so clients and CPI callers share its constants instead of re-deriving them:

```toml
[dependencies]
bio-did-registry = { version = "0.1", features = ["no-entrypoint"] }
```

`no-entrypoint` leaves out the entrypoint, allocator, and panic handler so
the crate links into an ordinary binary or another program. It exports:

- `ID` - the program address
- `ix` - the thirteen instruction discriminators
- `state` - the account discriminators, PDA seeds, size limits, verification
  method type and flag constants, the `Sections` parser for the account
  layout, the `KeyBufferRef` header parser, and `owned_subject` for the
  subject an `initialize_owned` creates
- `events` - the three event discriminators
- `error::DidError` - the domain errors behind custom codes `6000..=6017`

The crate is `no_std` on the Solana target and a normal library elsewhere.

## Security

This program has **not yet received an external audit**. See
[SECURITY.md](SECURITY.md) for how to report vulnerabilities.

Core invariants enforced on-chain:

- only `capabilityInvocation` Ed25519 keys may mutate a document
- the last update authority can never be removed or de-flagged
- `PROTECTED` verification methods only change under their own key
- a sponsor who pays for `initialize` gains no control over the DID
- a key subject is a key: `initialize` refuses off-curve addresses, so no
  DID is ever born without an authority and no owned subject can be
  squatted ahead of its owner
- an owned DID is created only under its authority's signature
- deactivation is permanent (tombstone, never account closure)
- a key buffer is bound to the authority that opened it and to one DID

## Building and Verifying

```console
cargo build-sbf --manifest-path program/Cargo.toml
```

The deployed program can be verified against this source with
[solana-verify](https://solana.com/developers/guides/advanced/verified-builds):

```console
solana-verify build --library-name bio_did_registry
solana-verify get-program-hash -ud H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6
```

## Testing

Integration tests run under [LiteSVM](https://github.com/LiteSVM/litesvm). Instructions are hand-encoded and accounts are decoded by an independent 
parser, so the tests pin the wire format itself:

```console
cargo build-sbf --manifest-path program/Cargo.toml
cargo test
cargo test --test compute_units -- --nocapture
```

## Compute Units

Baselines measured with the `compute_units` test (rounded to hundreds;
`initialize` and `create_key_buffer` vary with the PDA bump search). The
binary is ~93 KB and the per edit cost is independent of document size.

| Instruction | Estimated Cost |
| --- | --- |
| `initialize` | 3600+ |
| `initialize_owned` | 5200+ |
| `add_verification_method` (Ed25519) | 4900 |
| `create_key_buffer` (ML-DSA-87, 2.5 KB) | 5600+ |
| `write_key_buffer` (900 B chunk) | 1900 |
| `add_verification_method_from_buffer` (2.5 KB key) | 6600 |
| `close_key_buffer` | 1800 |
| `remove_verification_method` | 3500 |
| `set_verification_method_flags` | 3100 |
| `add_service` | 5900 |
| `remove_service` | 3400 |
| `set_controllers` (2 native + 2 external) | 5700 |
| `deactivate` | 2900 |

## License

[MIT](LICENSE)
