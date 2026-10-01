//! Replace the controller sets under an authority's signature. The two borsh
//! vectors in the instruction args are byte identical to their on-chain form, so
//! after validation they are copied in verbatim. The tail, which holds the
//! verification methods and services, is shifted by the size delta.

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
        subject,
    } = Update::try_from(accounts)?;

    // The borsh args are native_controllers: Vec<Pubkey> and other_controllers:
    // Vec<String>, parsed structurally into stack-bounded slices. The count limits
    // are enforced below the authority check so error precedence stays stable.
    let mut r = Reader::<Args>::new(args);
    let native_count = r.u32()? as usize;
    let mut natives: [&[u8]; MAX_NATIVE_CONTROLLERS] = [&[]; MAX_NATIVE_CONTROLLERS];
    let native_overflow = native_count > MAX_NATIVE_CONTROLLERS;
    // The loops below advance the arg cursor, so they must run for the full
    // on-wire count even when it exceeds the storable maximum.
    #[allow(clippy::needless_range_loop)]
    for i in 0..native_count {
        let key = r.bytes(32)?;
        if !native_overflow {
            natives[i] = key;
        }
    }
    let other_count = r.u32()? as usize;
    let mut others: [&[u8]; MAX_OTHER_CONTROLLERS] = [&[]; MAX_OTHER_CONTROLLERS];
    let other_overflow = other_count > MAX_OTHER_CONTROLLERS;
    #[allow(clippy::needless_range_loop)]
    for i in 0..other_count {
        let s = r.str()?;
        if !other_overflow {
            others[i] = s;
        }
    }
    let new_sections_len = r.offset();
    r.finish()?;
    let signer_key = authority.address().as_array();

    let (old_len, tail_start) = {
        let data = did_account.try_borrow()?;
        let doc = DidView::parse(&data)?;
        doc.require_authority(signer_key)?;
        let s = doc.sections();
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
            // did:bio controllers must use the native pubkey form, and
            // everything else must be a DID of some other method.
            require(valid_external_controller(c), DidError::InvalidController)?;
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
