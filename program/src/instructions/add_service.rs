//! Add a service endpoint (authority required). Services live at the tail of
//! the account, so this is a pure append - no bytes move.

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

    // Borsh args: Service { fragment, service_type, endpoint }
    let mut off = 0usize;
    let fragment = ix_read_str(args, &mut off)?;
    let service_type = ix_read_str(args, &mut off)?;
    let endpoint = ix_read_str(args, &mut off)?;
    let signer_key: &[u8] = authority.address().as_ref();
    let entry_len = service_space(fragment.len(), service_type.len(), endpoint.len());

    let (old_len, svc_count_pos, svc_count) = {
        let data = did_account.try_borrow()?;
        let s = Sections::parse(&data)?;
        require_authority(&data, &s, signer_key.try_into().unwrap())?;
        require(s.svc_count < MAX_SERVICES, DidError::TooManyServices)?;
        require(valid_fragment(fragment), DidError::InvalidFragment)?;
        require_fragment_free(&data, &s, fragment)?;
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
        let mut w = old_len;
        for part in [fragment, service_type, endpoint] {
            data[w..w + 4].copy_from_slice(&(part.len() as u32).to_le_bytes());
            w += 4;
            data[w..w + part.len()].copy_from_slice(part);
            w += part.len();
        }
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
