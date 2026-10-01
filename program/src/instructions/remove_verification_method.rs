//! Remove a verification method by fragment under an authority's signature.
//! The account shrinks and the freed rent is refunded to the payer.

use pinocchio::{
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
    let Update {
        payer,
        authority,
        did_account,
        controller,
        subject,
    } = Update::try_from(accounts)?;

    let mut r = Reader::<Args>::new(args);
    let fragment = r.str()?;
    r.finish()?;
    let signer_key = authority.address().as_array();

    let (span_start, span_end, old_len, vm_count_pos, vm_count) = {
        let data = did_account.try_borrow()?;
        let doc = DidView::parse(&data)?;
        authorize(&doc, signer_key, controller)?;
        let vm = doc
            .find_vm(fragment)
            .ok_or(DidError::VerificationMethodNotFound)?;

        // Protected methods may only be removed by their own key.
        if vm.flags & VM_FLAG_PROTECTED != 0 {
            require(vm.key == signer_key, DidError::ProtectedVerificationMethod)?;
        }
        // Never orphan the DID. At least one capabilityInvocation Ed25519
        // key must survive the removal.
        if vm.is_authority() {
            require(doc.authority_count() > 1, DidError::LastAuthority)?;
        }
        let s = doc.sections();
        (vm.start, vm.end, s.end, s.vm_count_pos, s.vm_count)
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
