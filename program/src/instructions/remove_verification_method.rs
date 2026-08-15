//! Remove a verification method by fragment (authority required). Shrinks
//! the account; the freed rent is refunded to the payer.

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use crate::{error::*, events, instructions::shared::*, state::*};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [payer, authority, did_account, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_payer(payer)?;
    check_authority_signer(authority)?;
    check_system_program(system_program)?;
    let subject = verify_did_account(did_account)?;

    let mut off = 0usize;
    let fragment = ix_read_str(args, &mut off)?;
    let signer_key: &[u8] = authority.address().as_ref();

    let (span_start, span_end, old_len, vm_count_pos, vm_count) = {
        let data = did_account.try_borrow()?;
        let s = Sections::parse(&data)?;
        require_authority(&data, &s, signer_key.try_into().unwrap())?;

        let mut found: Option<(usize, usize, u16, bool, bool)> = None;
        for_each_vm(&data, &s, |vm| {
            if vm.fragment == fragment {
                found = Some((
                    vm.start,
                    vm.end,
                    vm.flags,
                    vm.key == signer_key,
                    vm.method_type == VM_TYPE_ED25519
                        && vm.flags & VM_FLAG_CAPABILITY_INVOCATION != 0,
                ));
                return Ok(false);
            }
            Ok(true)
        })?;
        let (start, end, flags, is_own_key, removes_authority) =
            found.ok_or(DidError::VerificationMethodNotFound)?;

        // Protected methods may only be removed by their own key.
        if flags & VM_FLAG_PROTECTED != 0 {
            require(is_own_key, DidError::ProtectedVerificationMethod)?;
        }
        // Never orphan the DID: at least one capabilityInvocation Ed25519
        // key must survive the removal.
        if removes_authority {
            require(authority_count(&data, &s)? > 1, DidError::LastAuthority)?;
        }
        (start, end, s.end, s.vm_count_pos, s.vm_count)
    };

    let entry_len = span_end - span_start;
    let now = Clock::get()?.unix_timestamp;
    let new_version;
    {
        let mut data = did_account.try_borrow_mut()?;
        data.copy_within(span_end..old_len, span_start);
        data[vm_count_pos..vm_count_pos + 4]
            .copy_from_slice(&((vm_count - 1) as u32).to_le_bytes());
        touch(&mut data, now);
        new_version = version(&data);
    }
    shrink(did_account, payer, old_len - entry_len)?;

    events::emit(
        &events::DID_MODIFIED,
        did_account.address(),
        &subject,
        new_version,
    );
    Ok(())
}
