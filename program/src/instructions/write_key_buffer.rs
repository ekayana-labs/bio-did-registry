//! Append one chunk of key material to a key buffer. Chunks arrive in
//! order, each continuing exactly where the previous one ended, so the
//! buffer never has holes and `written` is always a prefix of the key.
//!
//! ABI: [authority, key_buffer]

use pinocchio::{error::ProgramError, AccountView, ProgramResult};

use crate::{error::*, instructions::shared::*, state::*};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [authority, key_buffer, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_authority_signer(authority)?;
    verify_key_buffer(key_buffer, authority.address(), None)?;

    // Borsh args: offset: u32, chunk: Vec<u8>
    let mut off = 0usize;
    let offset = ix_read_u32(args, &mut off)? as usize;
    let chunk = ix_read_len_prefixed(args, &mut off)?;

    let mut data = key_buffer.try_borrow_mut()?;
    let (written, key_len) = {
        let kb = KeyBufferRef::parse(&data)?;
        (kb.written, kb.key_len)
    };
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
