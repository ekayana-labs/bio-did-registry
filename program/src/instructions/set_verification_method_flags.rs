//! Replace the relationship and property flags of a verification method. It is
//! the only mutation that never resizes, so it takes `[authority, did_account]`.

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
    let [authority, did_account, rest @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_authority_signer(authority)?;
    let subject = verify_did_account(did_account)?;

    let mut r = Reader::<Args>::new(args);
    let fragment = r.str()?;
    let new_flags = r.u16()?;
    r.finish()?;
    let signer_key = authority.address().as_array();

    let now = Clock::get()?.unix_timestamp;
    let new_version;
    {
        let mut data = did_account.try_borrow_mut()?;
        let flags_pos = {
            let doc = DidView::parse(&data)?;
            authorize(&doc, signer_key, rest.first())?;
            let vm = doc
                .find_vm(fragment)
                .ok_or(DidError::VerificationMethodNotFound)?;

            // Changing a protected method, or granting or revoking protection,
            // requires the method's own key as authority.
            if (vm.flags | new_flags) & VM_FLAG_PROTECTED != 0 {
                require(vm.key == signer_key, DidError::ProtectedVerificationMethod)?;
            }
            validate_vm_flags(vm.method_type, new_flags)?;

            // Never orphan the DID by stripping the last capabilityInvocation key.
            let stays_authority = new_flags & VM_FLAG_CAPABILITY_INVOCATION != 0;
            if vm.is_authority() && !stays_authority {
                require(doc.authority_count() > 1, DidError::LastAuthority)?;
            }
            vm.flags_pos
        };

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
