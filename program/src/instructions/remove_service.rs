//! Remove a service endpoint by fragment (authority required). Shrinks the
//! account; the freed rent is refunded to the payer.

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

    let (span_start, span_end, old_len, svc_count_pos, svc_count) = {
        let data = did_account.try_borrow()?;
        let s = Sections::parse(&data)?;
        require_authority(&data, &s, signer_key.try_into().unwrap())?;

        let mut found: Option<(usize, usize)> = None;
        for_each_service(&data, &s, |svc| {
            if svc.fragment == fragment {
                found = Some((svc.start, svc.end));
                return Ok(false);
            }
            Ok(true)
        })?;
        let (start, end) = found.ok_or(DidError::ServiceNotFound)?;
        (start, end, s.end, s.svc_count_pos, s.svc_count)
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
