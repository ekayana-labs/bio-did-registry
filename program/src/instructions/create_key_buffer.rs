//! Open a key buffer: a staging account for a verification method whose key
//! does not fit in one transaction (ML-DSA-87 is 2592 bytes; a transaction
//! is 1232). Everything that can be checked without the key material is
//! checked here, so an upload that cannot succeed fails before any chunk is
//! sent. The buffer is funded by the payer and bound to the signing
//! authority: only that key may write, finish, or close it.
//!
//! ABI: [payer, authority, did_account, key_buffer, system_program]

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

use crate::{error::*, instructions::shared::*, state::*};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [payer, authority, did_account, key_buffer, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_payer(payer)?;
    check_authority_signer(authority)?;
    check_system_program(system_program)?;
    load_did_account(did_account)?;
    if !key_buffer.is_writable() {
        return Err(ProgramError::Immutable);
    }

    // Borsh args: fragment: String, method_type: u8, flags: u16, key_len: u32
    let mut off = 0usize;
    let fragment = ix_read_str(args, &mut off)?;
    let method_type = ix_read_u8(args, &mut off)?;
    let flags = ix_read_u16(args, &mut off)?;
    let key_len = ix_read_u32(args, &mut off)? as usize;
    let expected_len = expected_key_len(method_type).ok_or(ProgramError::InvalidInstructionData)?;
    let signer_key: &[u8] = authority.address().as_ref();

    {
        let data = did_account.try_borrow()?;
        let s = Sections::parse(&data)?;
        require_authority(&data, &s, signer_key.try_into().unwrap())?;
        require(
            s.vm_count < MAX_VERIFICATION_METHODS,
            DidError::TooManyVerificationMethods,
        )?;
        require(valid_fragment(fragment), DidError::InvalidFragment)?;
        require_fragment_free(&data, &s, fragment)?;
        require(key_len == expected_len, DidError::InvalidKeyLength)?;
        validate_vm_flags(method_type, flags)?;
        // A protected method must carry the signer's own 32 byte key, which
        // a larger key can never satisfy when the buffer is finished.
        if flags & VM_FLAG_PROTECTED != 0 {
            require(key_len == 32, DidError::ProtectedVerificationMethod)?;
        }
    }

    let (pda, bump) = Address::find_program_address(
        &[
            KEY_BUFFER_SEED,
            did_account.address().as_ref(),
            authority.address().as_ref(),
        ],
        &crate::ID,
    );
    if key_buffer.address() != &pda {
        return Err(ProgramError::InvalidSeeds);
    }
    // One buffer per authority and DID at a time.
    if !key_buffer.owned_by(&pinocchio_system::ID) || key_buffer.data_len() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let space = KEY_BUFFER_HEADER + key_len;
    let rent_min = rent_minimum_balance(space)?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(KEY_BUFFER_SEED),
        Seed::from(did_account.address().as_ref()),
        Seed::from(authority.address().as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];

    if key_buffer.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: key_buffer,
            lamports: rent_min,
            space: space as u64,
            owner: &crate::ID,
        }
        .invoke_signed(&[Signer::from(&seeds)])?;
    } else {
        // The address was pre-funded: top up to the rent minimum, then
        // allocate + assign under the PDA signature.
        let deficit = rent_min.saturating_sub(key_buffer.lamports());
        if deficit > 0 {
            Transfer {
                from: payer,
                to: key_buffer,
                lamports: deficit,
            }
            .invoke()?;
        }
        Allocate {
            account: key_buffer,
            space: space as u64,
        }
        .invoke_signed(&[Signer::from(&seeds)])?;
        Assign {
            account: key_buffer,
            owner: &crate::ID,
        }
        .invoke_signed(&[Signer::from(&seeds)])?;
    }

    let mut data = key_buffer.try_borrow_mut()?;
    if data.len() != space {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[0..8].copy_from_slice(&KEY_BUFFER_DISCRIMINATOR);
    data[KB_OFF_DID_ACCOUNT..KB_OFF_DID_ACCOUNT + 32]
        .copy_from_slice(did_account.address().as_ref());
    data[KB_OFF_AUTHORITY..KB_OFF_AUTHORITY + 32].copy_from_slice(signer_key);
    data[KB_OFF_BUMP] = bump;
    data[KB_OFF_METHOD_TYPE] = method_type;
    data[KB_OFF_FLAGS..KB_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
    data[KB_OFF_KEY_LEN..KB_OFF_KEY_LEN + 4].copy_from_slice(&(key_len as u32).to_le_bytes());
    data[KB_OFF_WRITTEN..KB_OFF_WRITTEN + 4].copy_from_slice(&0u32.to_le_bytes());
    data[KB_OFF_FRAGMENT_LEN..KB_OFF_FRAGMENT_LEN + 4]
        .copy_from_slice(&(fragment.len() as u32).to_le_bytes());
    data[KB_OFF_FRAGMENT..KB_OFF_FRAGMENT + fragment.len()].copy_from_slice(fragment);
    Ok(())
}
