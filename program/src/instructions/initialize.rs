//! Materialize the on-chain account for `did:bio:<base58(subject)>`.
//!
//! Permissionless: any payer may create the account (sponsored creation),
//! but the stored document is exactly the generative default - the subject
//! key itself is the only verification method and only authority - so a
//! third party initializer gains no control.

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

use crate::{events, instructions::shared::*, state::*};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [payer, did_account, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_payer(payer)?;
    check_system_program(system_program)?;
    if !did_account.is_writable() {
        return Err(ProgramError::Immutable);
    }

    let subject: &[u8; 32] = args
        .get(0..32)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .unwrap();

    let (pda, bump) = Address::find_program_address(&[DID_SEED, subject], &crate::ID);
    if did_account.address() != &pda {
        return Err(ProgramError::InvalidSeeds);
    }
    // `initialize` targets an untouched system account; anything else is
    // already initialized (or a deactivated tombstone, which must never
    // resurrect).
    if !did_account.owned_by(&pinocchio_system::ID) || did_account.data_len() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let rent_min = rent_minimum_balance(INITIAL_SPACE)?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(DID_SEED),
        Seed::from(subject.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];

    if did_account.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: did_account,
            lamports: rent_min,
            space: INITIAL_SPACE as u64,
            owner: &crate::ID,
        }
        .invoke_signed(&[Signer::from(&seeds)])?;
    } else {
        // The address was pre-funded: top up to the rent minimum, then
        // allocate + assign under the PDA signature.
        let deficit = rent_min.saturating_sub(did_account.lamports());
        if deficit > 0 {
            Transfer {
                from: payer,
                to: did_account,
                lamports: deficit,
            }
            .invoke()?;
        }
        Allocate {
            account: did_account,
            space: INITIAL_SPACE as u64,
        }
        .invoke_signed(&[Signer::from(&seeds)])?;
        Assign {
            account: did_account,
            owner: &crate::ID,
        }
        .invoke_signed(&[Signer::from(&seeds)])?;
    }

    let now = Clock::get()?.unix_timestamp;
    {
        let mut data = did_account.try_borrow_mut()?;
        if data.len() != INITIAL_SPACE {
            return Err(ProgramError::AccountDataTooSmall);
        }
        data[0..8].copy_from_slice(&ACCOUNT_DISCRIMINATOR);
        data[OFF_VERSION..OFF_VERSION + 8].copy_from_slice(&1u64.to_le_bytes());
        data[OFF_BUMP] = bump;
        data[OFF_SUBJECT..OFF_SUBJECT + 32].copy_from_slice(subject);
        data[OFF_DEACTIVATED] = 0;
        data[OFF_UPDATED_AT..OFF_UPDATED_AT + 8].copy_from_slice(&now.to_le_bytes());
        let mut off = OFF_SECTIONS;
        // native_controllers: [], other_controllers: []
        data[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        off += 4;
        data[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        off += 4;
        // verification_methods: [ { "default", Ed25519, VM_FLAGS_DEFAULT, subject } ]
        data[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
        off += 4;
        data[off..off + 4].copy_from_slice(&(DEFAULT_FRAGMENT.len() as u32).to_le_bytes());
        off += 4;
        data[off..off + DEFAULT_FRAGMENT.len()].copy_from_slice(DEFAULT_FRAGMENT);
        off += DEFAULT_FRAGMENT.len();
        data[off] = VM_TYPE_ED25519;
        off += 1;
        data[off..off + 2].copy_from_slice(&VM_FLAGS_DEFAULT.to_le_bytes());
        off += 2;
        data[off..off + 4].copy_from_slice(&32u32.to_le_bytes());
        off += 4;
        data[off..off + 32].copy_from_slice(subject);
        off += 32;
        // services: []
        data[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        debug_assert_eq!(off + 4, INITIAL_SPACE);
    }

    events::emit(&events::DID_INITIALIZED, did_account.address(), subject, 1);
    Ok(())
}
