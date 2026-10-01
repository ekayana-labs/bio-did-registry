//! Replace the type and endpoint of a service under an authority's
//! signature. The entry keeps its place, the services after it move by the
//! size difference, and rent is settled against the payer. A metadata CID
//! change is then one instruction and one version.
//!
//! The accounts are `[payer, authority, did_account, system_program]` and
//! the args are a `Service`, as for `add_service`.

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
    let service_type = r.str()?;
    let endpoint = r.str()?;
    r.finish()?;
    let signer_key = authority.address().as_array();

    let (start, end, old_len) = {
        let data = did_account.try_borrow()?;
        let doc = DidView::parse(&data)?;
        authorize(&doc, signer_key, controller)?;
        let svc = doc
            .find_service(fragment)
            .ok_or(DidError::ServiceNotFound)?;
        require(
            valid_uri_ascii(service_type, MAX_SERVICE_TYPE_LEN),
            DidError::InvalidServiceValue,
        )?;
        require(
            valid_uri_ascii(endpoint, MAX_ENDPOINT_LEN),
            DidError::InvalidServiceValue,
        )?;
        (svc.start, svc.end, doc.sections().end)
    };

    let entry_end = start + service_space(fragment.len(), service_type.len(), endpoint.len());
    let new_len = old_len - end + entry_end;
    if new_len > old_len {
        grow(did_account, payer, new_len)?;
    }
    let now = Clock::get()?.unix_timestamp;

    let new_version = {
        let mut data = did_account.try_borrow_mut()?;
        data.copy_within(end..old_len, entry_end);
        write_service(&mut data, start, fragment, service_type, endpoint);
        touch(&mut data, now);
        version(&data)
    };
    if new_len < old_len {
        shrink(did_account, payer, new_len)?;
    }

    events::emit(
        &events::DID_MODIFIED,
        did_account.address(),
        &subject,
        new_version,
    );
    Ok(())
}
