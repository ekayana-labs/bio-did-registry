# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-01

### Added

- `update_service` replaces a service's type and endpoint in place.
- An authority of a native controller may update the DIDs it controls,
  through the controller's registry account after the instruction's own.
- A program address may hold authority and sign through CPI.
- The `InvalidKey` error, code 6018.
- `client` builds every instruction off chain.
- `DidError::from_code` and `DidError::message` decode custom error codes.
- `DidView` reads a `DidAccount` through entry iterators.
- `reader::Reader` is the cursor the layout code reads with.
- `DidAccountHeader` and `KeyBufferHeader` define the layout offsets.

### Changed

- A protected method must keep `capabilityInvocation`.
- An Ed25519 key must be a curve point unless it signs the transaction.
- A secp256k1 key must be a compressed point.
- An ML-DSA-87 method may not carry `keyAgreement`.
- `DidError` is non-exhaustive, so later error codes are additive.
- The lifecycle in the compute unit report costs 41,169 CU, down from
  75,712.

### Deprecated

- The `state::read_*` and `instructions::shared::ix_read_*` helpers, in
  favor of `Reader`.
- `for_each_vm`, `for_each_service` and the free `require_authority`,
  `authority_count` and `require_fragment_free`, in favor of `DidView`.

## [0.1.2] - 2026-09-16

### Added

- `initialize_owned` creates a DID whose subject the program derives from
  the signing authority and a nonce.

### Changed

- `initialize` refuses subjects off the Ed25519 curve.
- Instruction arguments and accounts must be exact in length.
- `#default` is reserved for the founding key.
- External controllers must be `did:<method>:<id>`.
- Protection is limited to Ed25519 methods.

## [0.1.1] - 2026-09-09

### Added

- Key buffers upload keys larger than one transaction in chunks.

## [0.1.0] - 2026-09-04

First release, the Pinocchio build of the registry.

[Unreleased]: https://github.com/ekayana-labs/bio-did-registry/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ekayana-labs/bio-did-registry/releases/tag/v0.2.0
[0.1.2]: https://github.com/ekayana-labs/bio-did-registry/releases/tag/v0.1.2
[0.1.1]: https://github.com/ekayana-labs/bio-did-registry/releases/tag/v0.1.1
[0.1.0]: https://github.com/ekayana-labs/bio-did-registry/releases/tag/v0.1.0
