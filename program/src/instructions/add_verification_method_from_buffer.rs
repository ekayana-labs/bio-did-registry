//! Append the verification method staged in a complete key buffer to the
//! DID account, then close the buffer and refund its rent to the payer.
//! The rules of `add_verification_method` apply unchanged, evaluated
//! against the DID's state now rather than when the buffer was opened.
//!
//! ABI: [payer, authority, did_account, key_buffer, system_program]

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use crate::{error::*, events, instructions::shared::*, state::*};

pub fn process(accounts: &mut [AccountView], _args: &[u8]) -> ProgramResult {
    let [payer, authority, did_account, key_buffer, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_payer(payer)?;
    check_authority_signer(authority)?;
    check_system_program(system_program)?;
    let subject = verify_did_account(did_account)?;
    verify_key_buffer(key_buffer, authority.address(), Some(did_account.address()))?;
    let signer_key: &[u8] = authority.address().as_ref();

    // Header scalars and the fragment, copied out so the validation below
    // can borrow both accounts freely.
    let mut fragment_buf = [0u8; MAX_FRAGMENT_LEN];
    let (fragment_len, method_type, flags, key_len) = {
        let buf = key_buffer.try_borrow()?;
        let kb = KeyBufferRef::parse(&buf)?;
        require(kb.written == kb.key_len, DidError::KeyBufferIncomplete)?;
        fragment_buf[..kb.fragment.len()].copy_from_slice(kb.fragment);
        (kb.fragment.len(), kb.method_type, kb.flags, kb.key_len)
    };
    let fragment = &fragment_buf[..fragment_len];
    let expected_len = expected_key_len(method_type).ok_or(ProgramError::InvalidInstructionData)?;
    let entry_len = vm_space(fragment.len(), key_len);

    let (insert_at, old_len, vm_count_pos, vm_count) = {
        let data = did_account.try_borrow()?;
        let buf = key_buffer.try_borrow()?;
        let key = &buf[KB_OFF_KEY..KB_OFF_KEY + key_len];
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
        if flags & VM_FLAG_PROTECTED != 0 {
            require(key == signer_key, DidError::ProtectedVerificationMethod)?;
        }
        (s.svc_count_pos, s.end, s.vm_count_pos, s.vm_count)
    };

    grow(did_account, payer, old_len + entry_len)?;
    let now = Clock::get()?.unix_timestamp;

    let new_version;
    {
        let mut data = did_account.try_borrow_mut()?;
        let buf = key_buffer.try_borrow()?;
        let key = &buf[KB_OFF_KEY..KB_OFF_KEY + key_len];
        // Shift the services section right and write the new entry into the gap.
        data.copy_within(insert_at..old_len, insert_at + entry_len);
        let mut w = insert_at;
        data[w..w + 4].copy_from_slice(&(fragment.len() as u32).to_le_bytes());
        w += 4;
        data[w..w + fragment.len()].copy_from_slice(fragment);
        w += fragment.len();
        data[w] = method_type;
        w += 1;
        data[w..w + 2].copy_from_slice(&flags.to_le_bytes());
        w += 2;
        data[w..w + 4].copy_from_slice(&(key_len as u32).to_le_bytes());
        w += 4;
        data[w..w + key_len].copy_from_slice(key);
        data[vm_count_pos..vm_count_pos + 4]
            .copy_from_slice(&((vm_count + 1) as u32).to_le_bytes());
        touch(&mut data, now);
        new_version = version(&data);
    }

    close_to(key_buffer, payer)?;

    events::emit(
        &events::DID_MODIFIED,
        did_account.address(),
        &subject,
        new_version,
    );
    Ok(())
}
