//! Replace the controller sets (authority required). The two borsh vectors
//! in the instruction args are byte identical to their on-chain form, so
//! after validation they are copied in verbatim and the tail (verification
//! methods + services) is shifted by the size delta.

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

    // Borsh args: native_controllers: Vec<Pubkey>, other_controllers: Vec<String>.
    // Structural parse into stack-bounded slices; the count limits are
    // enforced below the authority check so error precedence stays stable.
    let mut off = 0usize;
    let native_count = ix_read_u32(args, &mut off)? as usize;
    let mut natives: [&[u8]; MAX_NATIVE_CONTROLLERS] = [&[]; MAX_NATIVE_CONTROLLERS];
    let native_overflow = native_count > MAX_NATIVE_CONTROLLERS;
    // The loops below must run for the full on-wire count (they advance the
    // arg cursor), even when the count exceeds the storable maximum.
    #[allow(clippy::needless_range_loop)]
    for i in 0..native_count {
        let key = ix_read_bytes(args, &mut off, 32)?;
        if !native_overflow {
            natives[i] = key;
        }
    }
    let other_count = ix_read_u32(args, &mut off)? as usize;
    let mut others: [&[u8]; MAX_OTHER_CONTROLLERS] = [&[]; MAX_OTHER_CONTROLLERS];
    let other_overflow = other_count > MAX_OTHER_CONTROLLERS;
    #[allow(clippy::needless_range_loop)]
    for i in 0..other_count {
        let s = ix_read_str(args, &mut off)?;
        if !other_overflow {
            others[i] = s;
        }
    }
    let new_sections_len = off;
    let signer_key: &[u8] = authority.address().as_ref();

    let (old_len, tail_start) = {
        let data = did_account.try_borrow()?;
        let s = Sections::parse(&data)?;
        require_authority(&data, &s, signer_key.try_into().unwrap())?;
        require(
            !native_overflow && !other_overflow,
            DidError::TooManyControllers,
        )?;
        for (i, key) in natives[..native_count].iter().enumerate() {
            // No self-control loops, no duplicates.
            require(*key != subject.as_ref(), DidError::InvalidController)?;
            require(!natives[..i].contains(key), DidError::InvalidController)?;
        }
        for (i, c) in others[..other_count].iter().enumerate() {
            // did:bio controllers must use the native (pubkey) form;
            // everything else must at least look like a DID.
            require(
                valid_uri_ascii(c, MAX_CONTROLLER_LEN)
                    && c.starts_with(b"did:")
                    && !c.starts_with(b"did:bio:"),
                DidError::InvalidController,
            )?;
            require(!others[..i].contains(c), DidError::InvalidController)?;
        }
        (s.end, s.vm_count_pos)
    };

    let old_sections_len = tail_start - OFF_SECTIONS;
    let new_len = old_len - old_sections_len + new_sections_len;
    let now = Clock::get()?.unix_timestamp;

    let new_version;
    if new_sections_len > old_sections_len {
        grow(did_account, payer, new_len)?;
        let mut data = did_account.try_borrow_mut()?;
        data.copy_within(tail_start..old_len, OFF_SECTIONS + new_sections_len);
        data[OFF_SECTIONS..OFF_SECTIONS + new_sections_len]
            .copy_from_slice(&args[..new_sections_len]);
        touch(&mut data, now);
        new_version = version(&data);
    } else {
        {
            let mut data = did_account.try_borrow_mut()?;
            data.copy_within(tail_start..old_len, OFF_SECTIONS + new_sections_len);
            data[OFF_SECTIONS..OFF_SECTIONS + new_sections_len]
                .copy_from_slice(&args[..new_sections_len]);
            touch(&mut data, now);
            new_version = version(&data);
        }
        if new_len < old_len {
            shrink(did_account, payer, new_len)?;
        }
    }

    events::emit(
        &events::DID_MODIFIED,
        did_account.address(),
        &subject,
        new_version,
    );
    Ok(())
}
