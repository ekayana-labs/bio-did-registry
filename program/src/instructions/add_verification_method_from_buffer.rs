//! Append the verification method staged in a complete key buffer to the
//! DID account, then close the buffer and refund its rent to the payer.
//! The rules of `add_verification_method` apply unchanged, evaluated
//! against the DID's state now rather than when the buffer was opened.
//!
//! The accounts are `[payer, authority, did_account, key_buffer, system_program]`.

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use crate::{
    error::*,
    events,
    instructions::shared::*,
    reader::{Args, Reader},
    state::*,
};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [payer, authority, did_account, key_buffer, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    Reader::<Args>::new(args).finish()?;
    check_payer(payer)?;
    check_authority_signer(authority)?;
    check_system_program(system_program)?;
    let subject = verify_did_account(did_account)?;
    verify_key_buffer(key_buffer, authority.address(), Some(did_account.address()))?;
    let signer_key = authority.address().as_array();

    // The header scalars and the fragment are copied out, since the write
    // below needs the DID account mutably while the key is read from the
    // buffer.
    let mut fragment_buf = [0u8; MAX_FRAGMENT_LEN];
    let (fragment_len, method_type, flags, key_len, s) = {
        let buf = key_buffer.try_borrow()?;
        let kb = KeyBufferRef::parse(&buf)?;
        require(kb.written == kb.key_len, DidError::KeyBufferIncomplete)?;
        expected_key_len(kb.method_type).ok_or(ProgramError::InvalidInstructionData)?;
        let method = NewMethod {
            fragment: kb.fragment,
            method_type: kb.method_type,
            flags: kb.flags,
            key_len: kb.key_len,
        };
        let data = did_account.try_borrow()?;
        let doc = DidView::parse(&data)?;
        doc.check_new_method(signer_key, &method)?;
        check_new_key(&method, kb.key(&buf), signer_key)?;
        fragment_buf[..kb.fragment.len()].copy_from_slice(kb.fragment);
        (
            kb.fragment.len(),
            kb.method_type,
            kb.flags,
            kb.key_len,
            *doc.sections(),
        )
    };
    let method = NewMethod {
        fragment: &fragment_buf[..fragment_len],
        method_type,
        flags,
        key_len,
    };

    grow(did_account, payer, s.end + vm_space(fragment_len, key_len))?;
    let now = Clock::get()?.unix_timestamp;

    let new_version = {
        let mut data = did_account.try_borrow_mut()?;
        let buf = key_buffer.try_borrow()?;
        insert_vm(
            &mut data,
            &s,
            &method,
            &buf[KB_OFF_KEY..KB_OFF_KEY + key_len],
        );
        touch(&mut data, now);
        version(&data)
    };

    close_to(key_buffer, payer)?;

    events::emit(
        &events::DID_MODIFIED,
        did_account.address(),
        &subject,
        new_version,
    );
    Ok(())
}
