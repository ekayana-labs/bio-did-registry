//! Discard a key buffer and refund its rent to the payer. Only the authority
//! the buffer is bound to may close it. The DID account is not involved, so
//! an abandoned upload can be reclaimed even after the DID was deactivated
//! or the authority was rotated out.
//!
//! The accounts are `[payer, authority, key_buffer]`.

use pinocchio::{error::ProgramError, AccountView, ProgramResult};

use crate::{
    instructions::shared::*,
    reader::{Args, Reader},
};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [payer, authority, key_buffer, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    Reader::<Args>::new(args).finish()?;
    check_payer(payer)?;
    check_authority_signer(authority)?;
    verify_key_buffer(key_buffer, authority.address(), None)?;
    close_to(key_buffer, payer)
}
