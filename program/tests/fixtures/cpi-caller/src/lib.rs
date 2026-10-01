//! A test program that forwards one instruction to the registry and signs
//! it as its program address `["authority"]`, the way a multisig or a DAO
//! vault acts. The registry's tests use it to exercise program authorities.
//!
//! The accounts are the registry program followed by the accounts of the
//! registry instruction. The data is the address's bump followed by the
//! registry instruction's data. Every account keeps its roles, except the
//! program address, which signs.

#![cfg_attr(target_os = "solana", no_std)]

use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};

pinocchio::program_entrypoint!(process_instruction);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

/// Seed of the program address that signs.
pub const AUTHORITY_SEED: &[u8] = b"authority";

const MAX_ACCOUNTS: usize = 8;

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let [registry, rest @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let (bump, payload) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let authority = Address::create_program_address(&[AUTHORITY_SEED, &[*bump]], program_id)
        .map_err(|_| ProgramError::InvalidSeeds)?;
    if rest.len() > MAX_ACCOUNTS {
        return Err(ProgramError::InvalidArgument);
    }
    let rest = &*rest;
    let metas: [InstructionAccount; MAX_ACCOUNTS] = core::array::from_fn(|i| match rest.get(i) {
        Some(account) => InstructionAccount::new(
            account.address(),
            account.is_writable(),
            account.is_signer() || account.address() == &authority,
        ),
        None => InstructionAccount::readonly(registry.address()),
    });
    let instruction = InstructionView {
        program_id: registry.address(),
        data: payload,
        accounts: &metas[..rest.len()],
    };
    let bump = [*bump];
    let seeds = [Seed::from(AUTHORITY_SEED), Seed::from(&bump[..])];
    invoke_signed_with_bounds::<MAX_ACCOUNTS, _>(&instruction, rest, &[Signer::from(&seeds)])
}
