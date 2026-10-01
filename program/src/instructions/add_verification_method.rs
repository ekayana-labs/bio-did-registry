//! Add a verification method under an authority's signature. The account
//! grows by the entry's exact size, funded by the payer.

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
    let [payer, authority, did_account, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_payer(payer)?;
    check_authority_signer(authority)?;
    check_system_program(system_program)?;
    let subject = verify_did_account(did_account)?;

    // The borsh args are VerificationMethod { fragment, method_type, flags, key_data }.
    let mut r = Reader::<Args>::new(args);
    let fragment = r.str()?;
    let method_type = r.u8()?;
    let flags = r.u16()?;
    let key_data = r.len_prefixed()?;
    r.finish()?;
    let expected_len = expected_key_len(method_type).ok_or(ProgramError::InvalidInstructionData)?;

    let signer_key = authority.address().as_array();
    let entry_len = vm_space(fragment.len(), key_data.len());

    let (insert_at, old_len, vm_count_pos, vm_count) = {
        let data = did_account.try_borrow()?;
        let doc = DidView::parse(&data)?;
        doc.require_authority(signer_key)?;
        let s = doc.sections();
        require(
            s.vm_count < MAX_VERIFICATION_METHODS,
            DidError::TooManyVerificationMethods,
        )?;
        require(valid_fragment(fragment), DidError::InvalidFragment)?;
        doc.require_fragment_free(fragment)?;
        require(key_data.len() == expected_len, DidError::InvalidKeyLength)?;
        validate_vm_flags(method_type, flags)?;
        // A method may only be born protected if it belongs to the signer,
        // so no co-authority can plant an unremovable key.
        if flags & VM_FLAG_PROTECTED != 0 {
            require(
                key_data == signer_key,
                DidError::ProtectedVerificationMethod,
            )?;
        }
        (s.svc_count_pos, s.end, s.vm_count_pos, s.vm_count)
    };

    grow(did_account, payer, old_len + entry_len)?;
    let now = Clock::get()?.unix_timestamp;

    let new_version;
    {
        let mut data = did_account.try_borrow_mut()?;
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
        data[w..w + 4].copy_from_slice(&(key_data.len() as u32).to_le_bytes());
        w += 4;
        data[w..w + key_data.len()].copy_from_slice(key_data);
        data[vm_count_pos..vm_count_pos + 4]
            .copy_from_slice(&((vm_count + 1) as u32).to_le_bytes());
        touch(&mut data, now);
        new_version = version(&data);
    }

    events::emit(
        &events::DID_MODIFIED,
        did_account.address(),
        &subject,
        new_version,
    );
    Ok(())
}
