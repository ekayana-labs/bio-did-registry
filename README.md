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
[`did:bio`](https://github.com/ekayana-labs/bio-did-spec) W3C DID method,
which gives decentralized identifiers to researchers, datasets and research
infrastructure.

| Information | Account Address |
| --- | --- |
| did:bio Registry Program | `H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6` |

Currently live on devnet.

## Overview

Every Ed25519 keypair is a DID. `did:bio:devnet:<base58-pubkey>` resolves
to a deterministic generative DID document at zero cost. Writing the
on-chain account, a PDA at `["bio-did", subject]` that starts at 124 bytes,
unlocks the features below.

- Key rotation adds and removes verification methods. The five W3C DID
  verification relationships (authentication, assertionMethod, keyAgreement,
  capabilityInvocation, capabilityDelegation) are stored as bitflags.
- Post quantum keys are ML-DSA-87 (FIPS 204) verification methods for
  long-lived off-chain assertions, uploaded in chunks through a key buffer.
- Services anchor research metadata, such as `BioMetadata -> ipfs://<cid>`
  or `DataverseRepository -> doi.org/...`. `update_service` replaces a
  service's type and endpoint in place, so a new CID is one instruction.
- Controllers link dataset DIDs to researcher and organization DIDs. An
  authority of a native controller may update the DIDs it controls.
- Permanent deactivation leaves a rent-refunding tombstone, so a
  deactivated DID can never resurrect as its generative document.

All mutations require an Ed25519 signature from a verification method
carrying the `capabilityInvocation` relationship, on the DID itself or on
one of its native controllers. `initialize` is
permissionless, so a platform can sponsor account creation while the subject
keeps sole control, because the created state is exactly the generative
document. The subject has to be a key. An address off the Ed25519 curve is
refused with `InvalidArgument`, since nothing could ever sign for the
document it would name.

A DID does not have to be a key. `initialize_owned(nonce)` derives the
subject from the signing authority as `["bio-did-owned", authority, nonce]`,
an off-curve program address, and makes that authority's key the document's
first verification method. A wallet then names a dataset, paper or claim it
owns, pays for and controls with one signature. See [Owned DIDs](#owned-dids).

The program is built with [Pinocchio](https://github.com/anza-xyz/pinocchio).
It is `no_std` and allocation-free (`no_allocator!`), and it edits account
data in place without ever deserializing the document. Accounts are
exact-size at all times. Every instruction reallocates to the minimal
serialized layout and settles the balance to exactly the rent-exempt
minimum. The payer funds growth and receives the refund when an account
shrinks.

## Wire format

The wire format is frozen. Golden vectors in the test suite and the
[`did-bio-core`](https://github.com/ekayana-labs/did-bio-core) resolver
crate pin it.

- Instruction discriminators are `sha256("global:<name>")[..8]`.
- Account discriminators are `sha256("account:DidAccount")[..8]` and
  `sha256("account:KeyBuffer")[..8]`.
- Events are `sha256("event:<Name>")[..8]` followed by the borsh fields,
  emitted through `sol_log_data`.
- Domain errors are custom program error codes `6000..=6018`.
- Instruction arguments are exact. Bytes past the last field are rejected
  as `InvalidInstructionData`, the way borsh's `try_from_slice` rejects them.

See the [did:bio method specification](https://github.com/ekayana-labs/bio-did-spec)
for the account layout, resolution algorithm, and security analysis.

## Large keys

An ML-DSA-87 public key is 2592 bytes and a Solana transaction is at most
1232, so post quantum keys cannot travel in `add_verification_method`. They
go through a staging account instead.

1. `create_key_buffer(fragment, type, flags, key_len)` opens a `KeyBuffer`
   PDA at `["bio-did-key", did_account, authority]`, funded by the payer and
   bound to the signing authority. Every rule that does not need the key
   bytes is checked here, so a doomed upload fails before any chunk is sent.
2. `write_key_buffer(offset, chunk)` appends chunks in order. Chunks of 900
   bytes keep each transaction under the limit, and an ML-DSA-87 key takes
   three.
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
asset means someone has to keep that key. An owned DID has no key.

```text
subject     = find_program_address(["bio-did-owned", authority, nonce_le], PROGRAM_ID)
did_account = find_program_address(["bio-did", subject], PROGRAM_ID)
```

`initialize_owned(nonce)` takes `[payer, authority, did_account,
system_program]`, requires the authority's signature, and writes the same
124-byte initial document as `initialize` with the authority's key as the
protected `#default` method. From then on the DID behaves like any other,
with services, controllers, key rotation, post-quantum keys and
deactivation. The subject is off the curve, so no generative document
exists for it and it resolves only through the registry. It is `notFound`
until the account is created and `deactivated` forever after a tombstone.
Because the authority must sign, nobody can register an owned DID in
another wallet's name, and the same nonce under two authorities yields two
unrelated DIDs.

## Controllers and program authorities

A DID's native controllers are other `did:bio` subjects. When the signer
is not one of the DID's own authorities, the program reads the account
after the instruction's own accounts as the registry account of a
controller. If that controller is listed, is not deactivated and holds the
signer as an authority, the update goes through. Only the controller's own
methods count, so control reaches one level. A protected method still
answers only to its own key, and the DID always keeps one authority of its
own. A lab DID can then manage the dataset DIDs it controls, and a rotation
in the lab reaches all of them at once.

A program can hold authority as well. Its program address has no private
key, so it signs through a CPI, the way a multisig or a DAO vault does. Such
an address is off the Ed25519 curve, and the program accepts an off-curve
key only when that key signs the transaction itself. A program therefore
creates its own owned DID with `initialize_owned` and acts on it, or on the
DIDs that DID controls, through CPI. The tests drive both through the
`cpi-caller` fixture.

## Using the crate

The program is published to [crates.io](https://crates.io/crates/bio-did-registry)
so clients and CPI callers share its constants instead of re-deriving them.

```toml
[dependencies]
bio-did-registry = { version = "0.1", features = ["no-entrypoint"] }
```

`no-entrypoint` leaves out the entrypoint, allocator, and panic handler so
the crate links into an ordinary binary or another program. It exports the
items below.

- `ID` is the program address.
- `ix` holds the fourteen instruction discriminators.
- `state` holds the account discriminators, PDA seeds, size limits,
  verification method type and flag constants, the header structs the
  offsets come from, `DidView` with its entry iterators for reading a
  `DidAccount`, the `KeyBufferRef` header parser, and `owned_subject` for
  the subject an `initialize_owned` creates.
- `reader` holds the bounds-checked cursor the layout code reads with.
- `events` holds the three event discriminators.
- `error::DidError` holds the domain errors behind custom codes
  `6000..=6018`, with `from_code` and `message` to decode them.
- `client`, off chain only, builds every instruction with its accounts in
  order, and `upload_key` returns the whole key buffer sequence.

The crate is `no_std` on the Solana target and a normal library elsewhere.

## Security

This program has not yet received an external audit. See
[SECURITY.md](SECURITY.md) for how to report vulnerabilities.

The program enforces these core invariants on-chain.

- Only `capabilityInvocation` Ed25519 keys may mutate a document, its own
  or those of a native controller one level up.
- The last update authority can never be removed or de-flagged.
- `PROTECTED` verification methods only change under their own key, so
  only Ed25519 methods, the kind that can sign a transaction, carry it. A
  protected method keeps `capabilityInvocation`, so its key can always
  change or remove it, and a controller cannot.
- An Ed25519 key is a curve point, unless it is a program address signing
  the transaction itself. A secp256k1 key is a compressed point. An
  ML-DSA-87 key never claims key agreement.
- `#default` names the founding key and nothing else. No instruction can
  add a method or service under that fragment, even after the founding
  method was rotated out.
- A sponsor who pays for `initialize` gains no control over the DID.
- A key subject is a key. `initialize` refuses off-curve addresses, so no
  DID is ever born without an authority and no owned subject can be
  squatted ahead of its owner.
- An owned DID is created only under its authority's signature.
- Deactivation is permanent. It leaves a tombstone and never closes the
  account.
- A key buffer is bound to the authority that opened it and to one DID.

## Building and Verifying

```console
cargo build-sbf --manifest-path program/Cargo.toml
```

The deployed program can be verified against this source with
[solana-verify](https://solana.com/developers/guides/advanced/verified-builds).

```console
solana-verify build --library-name bio_did_registry
solana-verify get-program-hash -ud H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6
```

## Testing

Integration tests run under [LiteSVM](https://github.com/LiteSVM/litesvm).
Instructions are hand-encoded and accounts are decoded by an independent
parser, so the tests pin the wire format itself.

```console
cargo build-sbf --manifest-path program/Cargo.toml
cargo build-sbf --manifest-path program/tests/fixtures/cpi-caller/Cargo.toml
cargo test
cargo test --test compute_units -- --nocapture
```

## Compute Units

Measured by the `compute_units` test with fixed keys, so the figures are
reproducible. An instruction that derives a PDA on chain pays about 350 CU
for every bump candidate the search rejects. The table says how many the
test keys hit, so a search that succeeds at the first candidate costs the
figure minus about 350 per rejection. The binary is ~92 KB.

| Instruction | CU |
| --- | --- |
| `initialize` (1 rejected bump) | 2918 |
| `initialize_owned` (two searches, 1 rejected bump) | 3136 |
| `add_verification_method` (Ed25519) | 3660 |
| `create_key_buffer` (ML-DSA-87, 2.5 KB, 2 rejected bumps) | 3715 |
| `write_key_buffer` (900 B chunk) | 497 |
| `add_verification_method_from_buffer` (2.5 KB key) | 3750 |
| `close_key_buffer` | 463 |
| `remove_verification_method` (2.5 KB key) | 1852 |
| `set_verification_method_flags` | 1493 |
| `add_service` | 4417 |
| `update_service` (new CID) | 2772 |
| `remove_service` | 1880 |
| `set_controllers` (2 native + 2 external) | 4383 |
| `deactivate` | 1498 |

An edit walks the entries before the one it touches and moves the bytes
after it, so the cost grows with the document. The same test measures a
document at every limit, 50,040 bytes with sixteen methods, sixteen of the
longest services and eight controllers of each kind.

| Instruction on a full document | CU |
| --- | --- |
| `set_verification_method_flags` (last method) | 2854 |
| `update_service` (last service) | 8911 |
| `remove_service` (first service) | 2709 |
| `add_service` (sixteenth) | 10945 |
| `remove_verification_method` (first ML-DSA-87) | 2865 |
| `add_verification_method` (sixteenth, Ed25519) | 5453 |
| `set_controllers` (8 + 8) | 17362 |
| `deactivate` | 2388 |

## License

[MIT](LICENSE)
