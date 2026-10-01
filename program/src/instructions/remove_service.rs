//! Remove a service endpoint by fragment under an authority's signature.
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
        subject,
    } = Update::try_from(accounts)?;

    let mut r = Reader::<Args>::new(args);
    let fragment = r.str()?;
    r.finish()?;
    let signer_key = authority.address().as_array();

    let (span_start, span_end, old_len, svc_count_pos, svc_count) = {
        let data = did_account.try_borrow()?;
        let doc = DidView::parse(&data)?;
        doc.require_authority(signer_key)?;
        let svc = doc
            .find_service(fragment)
            .ok_or(DidError::ServiceNotFound)?;
        let s = doc.sections();
        (svc.start, svc.end, s.end, s.svc_count_pos, s.svc_count)
    };

    let entry_len = span_end - span_start;
    let now = Clock::get()?.unix_timestamp;
    let new_version;
    {
        let mut data = did_account.try_borrow_mut()?;
        data.copy_within(span_end..old_len, span_start);
        data[svc_count_pos..svc_count_pos + 4]
            .copy_from_slice(&((svc_count - 1) as u32).to_le_bytes());
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
