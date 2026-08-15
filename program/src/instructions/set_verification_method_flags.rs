//! Replace the relationship/property flags of a verification method.
//! The only mutation that never resizes: ABI is [authority, did_account].

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use crate::{error::*, events, instructions::shared::*, state::*};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [authority, did_account, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_authority_signer(authority)?;
    let subject = verify_did_account(did_account)?;

    let mut off = 0usize;
    let fragment = ix_read_str(args, &mut off)?;
    let new_flags = ix_read_u16(args, &mut off)?;
    let signer_key: &[u8] = authority.address().as_ref();

    let now = Clock::get()?.unix_timestamp;
    let new_version;
    {
        let mut data = did_account.try_borrow_mut()?;
        let s = Sections::parse(&data)?;
        require_authority(&data, &s, signer_key.try_into().unwrap())?;

        let mut found: Option<(usize, u16, u8, bool)> = None;
        for_each_vm(&data, &s, |vm| {
            if vm.fragment == fragment {
                found = Some((vm.flags_pos, vm.flags, vm.method_type, vm.key == signer_key));
                return Ok(false);
            }
            Ok(true)
        })?;
        let (flags_pos, old_flags, method_type, is_own_key) =
            found.ok_or(DidError::VerificationMethodNotFound)?;

        // Changing a protected method, or granting/revoking protection,
        // requires the method's own key as authority.
        if (old_flags | new_flags) & VM_FLAG_PROTECTED != 0 {
            require(is_own_key, DidError::ProtectedVerificationMethod)?;
        }
        validate_vm_flags(method_type, new_flags)?;

        // Never orphan the DID by stripping the last capabilityInvocation key.
        let was_authority =
            method_type == VM_TYPE_ED25519 && old_flags & VM_FLAG_CAPABILITY_INVOCATION != 0;
        let stays_authority = new_flags & VM_FLAG_CAPABILITY_INVOCATION != 0;
        if was_authority && !stays_authority {
            require(authority_count(&data, &s)? > 1, DidError::LastAuthority)?;
        }

        data[flags_pos..flags_pos + 2].copy_from_slice(&new_flags.to_le_bytes());
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
