//! did-bio-registry - the Solana verifiable data registry backing the
//! `did:bio` DID method (W3C DID 1.0).
//!
//! One PDA per DID, seeds = `["bio-did", subject]`. Every Ed25519 key is a
//! resolvable ("generative") DID at zero cost; initializing the on-chain
//! account unlocks key rotation, additional verification methods (including
//! post-quantum ML-DSA-87), service endpoints, controllers, and permanent
//! tombstone deactivation. All mutations require an Ed25519 signature from a
//! verification method carrying the `capabilityInvocation` relationship.
//!
//! Built on [Pinocchio](https://github.com/anza-xyz/pinocchio): accounts are
//! edited *in place* - the document is never deserialized onto the heap. The
//! program is `no_std`, allocation-free (`no_allocator!`), and its only
//! dependencies are the Pinocchio SDK crates.
//!
//! The wire format (instruction/account/event discriminators, borsh account
//! layout, error codes 6000..6014) is frozen and pinned by the golden
//! vectors in this repository's test suite; deployed resolvers and clients
//! depend on every byte of it.

#![no_std]

pub mod error;
pub mod events;
pub mod instructions;
pub mod state;

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

#[cfg(not(feature = "no-entrypoint"))]
pinocchio::program_entrypoint!(process_instruction);
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::no_allocator!();
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::nostd_panic_handler!();

/// Program ID: H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6
pub const ID: Address = Address::new_from_array(five8_const::decode_32_const(
    "H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6",
));

/// Instruction discriminators: sha256("global:<name>")[..8].
pub mod ix {
    pub const INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
    pub const ADD_VERIFICATION_METHOD: [u8; 8] = [213, 200, 190, 61, 28, 104, 245, 25];
    pub const REMOVE_VERIFICATION_METHOD: [u8; 8] = [33, 238, 66, 183, 62, 210, 133, 150];
    pub const SET_VERIFICATION_METHOD_FLAGS: [u8; 8] = [16, 188, 26, 223, 241, 131, 192, 223];
    pub const ADD_SERVICE: [u8; 8] = [133, 207, 106, 32, 91, 111, 153, 30];
    pub const REMOVE_SERVICE: [u8; 8] = [19, 102, 8, 231, 40, 141, 9, 110];
    pub const SET_CONTROLLERS: [u8; 8] = [65, 40, 24, 8, 30, 81, 20, 179];
    pub const DEACTIVATE: [u8; 8] = [44, 112, 33, 172, 113, 28, 142, 13];
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
        .split_at_checked(8)
        .ok_or(ProgramError::InvalidInstructionData)?;

    match disc.try_into().unwrap() {
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
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
