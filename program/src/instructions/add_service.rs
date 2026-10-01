//! Add a service endpoint under an authority's signature. Services live at
//! the tail of the account, so this is a pure append and no bytes move.

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

    // The borsh arguments are Service { fragment, service_type, endpoint }.
    let mut r = Reader::<Args>::new(args);
    let fragment = r.str()?;
    let service_type = r.str()?;
    let endpoint = r.str()?;
    r.finish()?;
    let signer_key = authority.address().as_array();
    let entry_len = service_space(fragment.len(), service_type.len(), endpoint.len());

    let (old_len, svc_count_pos, svc_count) = {
        let data = did_account.try_borrow()?;
        let doc = DidView::parse(&data)?;
        authorize(&doc, signer_key, controller)?;
        let s = doc.sections();
        require(s.svc_count < MAX_SERVICES, DidError::TooManyServices)?;
        require(valid_fragment(fragment), DidError::InvalidFragment)?;
        doc.require_fragment_free(fragment)?;
        require(
            valid_uri_ascii(service_type, MAX_SERVICE_TYPE_LEN),
            DidError::InvalidServiceValue,
        )?;
        require(
            valid_uri_ascii(endpoint, MAX_ENDPOINT_LEN),
            DidError::InvalidServiceValue,
        )?;
        (s.end, s.svc_count_pos, s.svc_count)
    };

    grow(did_account, payer, old_len + entry_len)?;
    let now = Clock::get()?.unix_timestamp;

    let new_version;
    {
        let mut data = did_account.try_borrow_mut()?;
        write_service(&mut data, old_len, fragment, service_type, endpoint);
        data[svc_count_pos..svc_count_pos + 4]
            .copy_from_slice(&((svc_count + 1) as u32).to_le_bytes());
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
