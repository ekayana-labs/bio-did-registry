//! Permanently deactivate a DID under an authority's signature. The account
//! is shrunk to a minimal tombstone that keeps `deactivated = true` forever.
//! A closed account could resurrect as a generative document, and a
//! tombstone never can. The freed rent is refunded to the payer.

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use crate::{
    events,
    instructions::shared::*,
    reader::{Args, Reader},
    state::*,
};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [payer, authority, did_account, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    Reader::<Args>::new(args).finish()?;
    check_payer(payer)?;
    check_authority_signer(authority)?;
    check_system_program(system_program)?;
    let subject = verify_did_account(did_account)?;
    let signer_key = authority.address().as_array();

    {
        let data = did_account.try_borrow()?;
        DidView::parse(&data)?.require_authority(signer_key)?;
    }

    let now = Clock::get()?.unix_timestamp;
    let new_version;
    {
        let mut data = did_account.try_borrow_mut()?;
        data[OFF_DEACTIVATED] = 1;
        // Empty all four vectors, so the 16 count bytes become the whole tail.
        data[OFF_SECTIONS..TOMBSTONE_SPACE].fill(0);
        touch(&mut data, now);
        new_version = version(&data);
    }
    shrink(did_account, payer, TOMBSTONE_SPACE)?;

    events::emit(
        &events::DID_DEACTIVATED,
        did_account.address(),
        &subject,
        new_version,
    );
    Ok(())
}
