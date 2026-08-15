//! Permanently deactivate a DID (authority required). The account is shrunk
//! to a minimal tombstone that keeps `deactivated = true` forever; unlike
//! closing the account, the DID can never resurrect as a generative
//! document. The freed rent is refunded to the payer.

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use crate::{events, instructions::shared::*, state::*};

pub fn process(accounts: &mut [AccountView], _args: &[u8]) -> ProgramResult {
    let [payer, authority, did_account, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_payer(payer)?;
    check_authority_signer(authority)?;
    check_system_program(system_program)?;
    let subject = verify_did_account(did_account)?;
    let signer_key: &[u8] = authority.address().as_ref();

    let old_len = {
        let data = did_account.try_borrow()?;
        let s = Sections::parse(&data)?;
        require_authority(&data, &s, signer_key.try_into().unwrap())?;
        s.end
    };

    let now = Clock::get()?.unix_timestamp;
    let new_version;
    {
        let mut data = did_account.try_borrow_mut()?;
        data[OFF_DEACTIVATED] = 1;
        // Empty all four vectors: the 16 count bytes become the whole tail.
        data[OFF_SECTIONS..TOMBSTONE_SPACE].fill(0);
        touch(&mut data, now);
        new_version = version(&data);
    }
    shrink(did_account, payer, TOMBSTONE_SPACE.min(old_len))?;

    events::emit(
        &events::DID_DEACTIVATED,
        did_account.address(),
        &subject,
        new_version,
    );
    Ok(())
}
