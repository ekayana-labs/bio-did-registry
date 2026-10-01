//! The Solana verifiable data registry backing the `did:bio` DID method
//! (W3C DID 1.0).
//!
//! Each DID has one PDA with the seeds `["bio-did", subject]`. Every Ed25519
//! key is a resolvable DID at zero cost, through its generative document.
//! Initializing the on-chain account unlocks key rotation, more verification
//! methods such as post-quantum ML-DSA-87 keys, service endpoints, controllers
//! and permanent tombstone deactivation. All mutations require an Ed25519
//! signature from a method carrying the `capabilityInvocation` relationship.
//!
//! The program is built on [Pinocchio](https://github.com/anza-xyz/pinocchio).
//! Accounts are edited in place, and the document is never deserialized onto
//! the heap. The program is `no_std` and allocation-free (`no_allocator!`),
//! and its only dependencies are the Pinocchio SDK crates.
//!
//! A key larger than one transaction, such as a 2592 byte ML-DSA-87 key, is
//! uploaded in chunks into a `KeyBuffer` staging account and appended to the
//! document by `add_verification_method_from_buffer`. See `state::KeyBufferRef`.
//!
//! `initialize_owned` creates a DID whose subject the program derives from
//! `["bio-did-owned", authority, nonce]`. The subject is off the curve and the
//! signing authority controls the DID from its first version, so one signature
//! names an asset its owner pays for. Such a DID has no generative document.
//!
//! The wire format is frozen. It covers the instruction, account and event
//! discriminators, the borsh account layout and the error codes 6000..6018. The
//! golden vectors in this repository's test suite pin it, and deployed resolvers
//! and clients depend on every byte of it. Additions only ever append.

#![cfg_attr(target_os = "solana", no_std)]

#[cfg(not(target_os = "solana"))]
pub mod client;
pub mod error;
pub mod events;
pub mod instructions;
pub mod reader;
pub mod state;

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

#[cfg(not(feature = "no-entrypoint"))]
pinocchio::program_entrypoint!(process_instruction);
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::no_allocator!();
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::nostd_panic_handler!();

/// The program ID, `H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6`.
pub const ID: Address = Address::new_from_array(five8_const::decode_32_const(
    "H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6",
));

/// Instruction discriminators, each `sha256("global:<name>")[..8]`.
pub mod ix {
    pub const INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
    pub const ADD_VERIFICATION_METHOD: [u8; 8] = [213, 200, 190, 61, 28, 104, 245, 25];
    pub const REMOVE_VERIFICATION_METHOD: [u8; 8] = [33, 238, 66, 183, 62, 210, 133, 150];
    pub const SET_VERIFICATION_METHOD_FLAGS: [u8; 8] = [16, 188, 26, 223, 241, 131, 192, 223];
    pub const ADD_SERVICE: [u8; 8] = [133, 207, 106, 32, 91, 111, 153, 30];
    pub const REMOVE_SERVICE: [u8; 8] = [19, 102, 8, 231, 40, 141, 9, 110];
    pub const SET_CONTROLLERS: [u8; 8] = [65, 40, 24, 8, 30, 81, 20, 179];
    pub const DEACTIVATE: [u8; 8] = [44, 112, 33, 172, 113, 28, 142, 13];
    // Chunked upload of keys larger than one transaction.
    pub const CREATE_KEY_BUFFER: [u8; 8] = [138, 70, 101, 189, 154, 98, 203, 23];
    pub const WRITE_KEY_BUFFER: [u8; 8] = [61, 88, 82, 10, 227, 249, 18, 117];
    pub const ADD_VERIFICATION_METHOD_FROM_BUFFER: [u8; 8] = [111, 184, 129, 9, 216, 207, 122, 90];
    pub const CLOSE_KEY_BUFFER: [u8; 8] = [6, 209, 103, 32, 78, 18, 70, 184];
    // A DID with a program-derived subject, controlled by its creator.
    pub const INITIALIZE_OWNED: [u8; 8] = [51, 133, 240, 229, 41, 137, 108, 91];
    // A service's type and endpoint, replaced in place.
    pub const UPDATE_SERVICE: [u8; 8] = [46, 169, 26, 33, 191, 78, 40, 221];
}

#[inline]
pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if program_id != &ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (disc, args) = instruction_data
        .split_first_chunk::<8>()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *disc {
        ix::INITIALIZE => instructions::initialize::process(accounts, args),
        ix::ADD_VERIFICATION_METHOD => {
            instructions::add_verification_method::process(accounts, args)
        }
        ix::REMOVE_VERIFICATION_METHOD => {
            instructions::remove_verification_method::process(accounts, args)
        }
        ix::SET_VERIFICATION_METHOD_FLAGS => {
            instructions::set_verification_method_flags::process(accounts, args)
        }
        ix::ADD_SERVICE => instructions::add_service::process(accounts, args),
        ix::REMOVE_SERVICE => instructions::remove_service::process(accounts, args),
        ix::SET_CONTROLLERS => instructions::set_controllers::process(accounts, args),
        ix::DEACTIVATE => instructions::deactivate::process(accounts, args),
        ix::CREATE_KEY_BUFFER => instructions::create_key_buffer::process(accounts, args),
        ix::WRITE_KEY_BUFFER => instructions::write_key_buffer::process(accounts, args),
        ix::ADD_VERIFICATION_METHOD_FROM_BUFFER => {
            instructions::add_verification_method_from_buffer::process(accounts, args)
        }
        ix::CLOSE_KEY_BUFFER => instructions::close_key_buffer::process(accounts, args),
        ix::INITIALIZE_OWNED => instructions::initialize_owned::process(accounts, args),
        ix::UPDATE_SERVICE => instructions::update_service::process(accounts, args),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    fn prefix(name: &str) -> [u8; 8] {
        let digest = Sha256::digest(name.as_bytes());
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        out
    }

    #[test]
    fn discriminators_are_hashes_of_their_names() {
        let instructions = [
            ("initialize", ix::INITIALIZE),
            ("add_verification_method", ix::ADD_VERIFICATION_METHOD),
            ("remove_verification_method", ix::REMOVE_VERIFICATION_METHOD),
            (
                "set_verification_method_flags",
                ix::SET_VERIFICATION_METHOD_FLAGS,
            ),
            ("add_service", ix::ADD_SERVICE),
            ("remove_service", ix::REMOVE_SERVICE),
            ("set_controllers", ix::SET_CONTROLLERS),
            ("deactivate", ix::DEACTIVATE),
            ("create_key_buffer", ix::CREATE_KEY_BUFFER),
            ("write_key_buffer", ix::WRITE_KEY_BUFFER),
            (
                "add_verification_method_from_buffer",
                ix::ADD_VERIFICATION_METHOD_FROM_BUFFER,
            ),
            ("close_key_buffer", ix::CLOSE_KEY_BUFFER),
            ("initialize_owned", ix::INITIALIZE_OWNED),
            ("update_service", ix::UPDATE_SERVICE),
        ];
        for (i, (name, discriminator)) in instructions.iter().enumerate() {
            assert_eq!(prefix(&format!("global:{name}")), *discriminator, "{name}");
            assert!(
                instructions[..i].iter().all(|(_, d)| d != discriminator),
                "{name} collides"
            );
        }
        assert_eq!(prefix("account:DidAccount"), state::ACCOUNT_DISCRIMINATOR);
        assert_eq!(prefix("account:KeyBuffer"), state::KEY_BUFFER_DISCRIMINATOR);
        assert_eq!(prefix("event:DidInitialized"), events::DID_INITIALIZED);
        assert_eq!(prefix("event:DidModified"), events::DID_MODIFIED);
        assert_eq!(prefix("event:DidDeactivated"), events::DID_DEACTIVATED);
    }
}
