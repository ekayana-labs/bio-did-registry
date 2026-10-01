//! Append one chunk of key material to a key buffer. Chunks arrive in
//! order, each continuing exactly where the previous one ended, so the
//! buffer never has holes and `written` is always a prefix of the key.
//!
//! The accounts are `[authority, key_buffer]`.

use pinocchio::{error::ProgramError, AccountView, ProgramResult};

use crate::{
    error::*,
    instructions::shared::*,
    reader::{Args, Reader},
    state::*,
};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [authority, key_buffer, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_authority_signer(authority)?;
    let (written, key_len) = check_key_buffer(key_buffer, authority.address(), None)?;

    // The borsh arguments are offset: u32 and chunk: Vec<u8>.
    let mut r = Reader::<Args>::new(args);
    let offset = r.u32()? as usize;
    let chunk = r.len_prefixed()?;
    r.finish()?;

    let mut data = key_buffer.try_borrow_mut()?;
    require(
        !chunk.is_empty() && offset == written,
        DidError::InvalidKeyChunk,
    )?;
    let end = offset
        .checked_add(chunk.len())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    require(end <= key_len, DidError::InvalidKeyChunk)?;

    data[KB_OFF_KEY + offset..KB_OFF_KEY + end].copy_from_slice(chunk);
    data[KB_OFF_WRITTEN..KB_OFF_WRITTEN + 4].copy_from_slice(&(end as u32).to_le_bytes());
    Ok(())
}
