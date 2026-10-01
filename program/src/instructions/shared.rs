//! Account validation and rent plumbing shared by the mutating instructions.
//!
//! The account order of each instruction follows.
//! - Realloc-family instructions take `[payer, authority, did_account, system_program]`.
//! - `set_verification_method_flags` takes `[authority, did_account]`.
//! - `initialize` takes `[payer, did_account, system_program]`.
//! - `create_key_buffer` and `add_verification_method_from_buffer` take
//!   `[payer, authority, did_account, key_buffer, system_program]`.
//! - `write_key_buffer` takes `[authority, key_buffer]`.
//! - `close_key_buffer` takes `[payer, authority, key_buffer]`.

use pinocchio::{
    error::ProgramError,
    sysvars::{get_sysvar, rent::RENT_ID},
    AccountView, Address, Resize,
};
use pinocchio_system::instructions::Transfer;

use crate::error::{require, DidError};
use crate::reader::{Account, Args, Reader};
use crate::state::{
    KeyBufferRef, ACCOUNT_DISCRIMINATOR, BASE_SPACE, DID_SEED, KEY_BUFFER_DISCRIMINATOR,
    KEY_BUFFER_HEADER, KEY_BUFFER_SEED, OFF_BUMP,
};

/// The accounts of an update that may resize the DID document,
/// `[payer, authority, did_account, system_program]`, after the checks every
/// such update makes.
pub struct Update<'a> {
    pub payer: &'a mut AccountView,
    pub authority: &'a AccountView,
    pub did_account: &'a mut AccountView,
    /// The DID's subject, which the events name.
    pub subject: [u8; 32],
}

impl<'a> TryFrom<&'a mut [AccountView]> for Update<'a> {
    type Error = ProgramError;

    #[inline(always)]
    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let [payer, authority, did_account, system_program, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        check_payer(payer)?;
        check_authority_signer(authority)?;
        check_system_program(system_program)?;
        let subject = verify_did_account(did_account)?;
        Ok(Self {
            payer,
            authority,
            did_account,
            subject,
        })
    }
}

/// The payer funds rent growth and receives shrink refunds, so it is a writable signer.
#[inline]
pub fn check_payer(payer: &AccountView) -> Result<(), ProgramError> {
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !payer.is_writable() {
        return Err(ProgramError::Immutable);
    }
    Ok(())
}

#[inline]
pub fn check_authority_signer(authority: &AccountView) -> Result<(), ProgramError> {
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

#[inline]
pub fn check_system_program(system_program: &AccountView) -> Result<(), ProgramError> {
    if system_program.address() != &pinocchio_system::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

/// Loads an existing `DidAccount` for mutation. It checks everything
/// [`load_did_account`] checks, and that the account is writable.
pub fn verify_did_account(did_account: &AccountView) -> Result<[u8; 32], ProgramError> {
    if !did_account.is_writable() {
        return Err(ProgramError::Immutable);
    }
    load_did_account(did_account)
}

/// Loads an existing `DidAccount` read-only. It must be owned by this program,
/// carry the `DidAccount` discriminator and sit at the PDA ["bio-did", subject]
/// with the stored bump. Returns the subject, which the events need.
pub fn load_did_account(did_account: &AccountView) -> Result<[u8; 32], ProgramError> {
    if !did_account.owned_by(&crate::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let data = did_account.try_borrow()?;
    if data.len() < BASE_SPACE || data[0..8] != ACCOUNT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut r = Reader::<Account>::at(&data, OFF_BUMP)?;
    let bump = r.u8()?;
    let subject = *r.array::<32>()?;
    // Only this program writes a `DidAccount`, and it created this one at
    // the address `find_program_address` returned with the stored bump, so
    // hashing the seeds again proves the address without the curve check.
    let expected = Address::derive_address(&[DID_SEED, &subject], Some(bump), &crate::ID);
    if did_account.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(subject)
}

/// Loads an existing `KeyBuffer`. The account must be writable, owned by
/// this program, carry the `KeyBuffer` discriminator, be bound to
/// `authority`, and to `did_account` when one is given, and sit at the PDA
/// ["bio-did-key", did_account, authority] with the stored bump.
pub fn verify_key_buffer(
    key_buffer: &AccountView,
    authority: &Address,
    did_account: Option<&Address>,
) -> Result<(), ProgramError> {
    check_key_buffer(key_buffer, authority, did_account).map(|_| ())
}

/// [`verify_key_buffer`], also returning how far the upload has come as
/// `(written, key_len)`.
pub(crate) fn check_key_buffer(
    key_buffer: &AccountView,
    authority: &Address,
    did_account: Option<&Address>,
) -> Result<(usize, usize), ProgramError> {
    if !key_buffer.is_writable() {
        return Err(ProgramError::Immutable);
    }
    if !key_buffer.owned_by(&crate::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let data = key_buffer.try_borrow()?;
    if data.len() < KEY_BUFFER_HEADER || data[0..8] != KEY_BUFFER_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    let kb = KeyBufferRef::parse(&data)?;
    require(
        kb.authority == authority.as_ref(),
        DidError::InvalidKeyBuffer,
    )?;
    if let Some(did) = did_account {
        require(kb.did_account == did.as_ref(), DidError::InvalidKeyBuffer)?;
    }
    // As in `load_did_account`, the program created the buffer at this bump.
    let expected = Address::derive_address(
        &[KEY_BUFFER_SEED, kb.did_account, kb.authority],
        Some(kb.bump),
        &crate::ID,
    );
    if key_buffer.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok((kb.written, kb.key_len))
}

/// Move every lamport to the payer and close the account.
pub fn close_to(account: &mut AccountView, payer: &mut AccountView) -> Result<(), ProgramError> {
    let credited = payer
        .lamports()
        .checked_add(account.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    payer.set_lamports(credited);
    account.set_lamports(0);
    account.close()
}

/// Rent-exempt minimum for `data_len`, read from the rent sysvar.
///
/// Handles both sysvar layouts. Current clusters use the classic 17-byte
/// `{ lamports_per_byte_year: u64, exemption_threshold: f64, burn_percent: u8 }`,
/// and `pinocchio::sysvars::rent::Rent` assumes the condensed 8-byte
/// `{ lamports_per_byte: u64 }`. Relying on pinocchio's `Rent::get()` alone
/// under-funds by the exemption threshold on a classic-layout runtime whose
/// threshold is 2.0.
pub fn rent_minimum_balance(data_len: usize) -> Result<u64, ProgramError> {
    const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
    // f64 2.0 in little-endian IEEE-754. Comparing the bits avoids float ops
    // when the threshold is 2.0.
    const TWO_F64_LE: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0x40];

    let bytes = ACCOUNT_STORAGE_OVERHEAD
        .checked_add(data_len as u64)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let mut classic = [0u8; 17];
    match get_sysvar(&mut classic, &RENT_ID, 0) {
        Ok(()) => {
            let mut r = Reader::<Account>::new(&classic);
            let lamports_per_byte_year = r.u64()?;
            let threshold = *r.array::<8>()?;
            let base = bytes
                .checked_mul(lamports_per_byte_year)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            if threshold == TWO_F64_LE {
                base.checked_mul(2).ok_or(ProgramError::ArithmeticOverflow)
            } else {
                let threshold = f64::from_le_bytes(threshold);
                if !(threshold.is_finite() && threshold >= 0.0) {
                    return Err(ProgramError::InvalidArgument);
                }
                Ok((base as f64 * threshold) as u64)
            }
        }
        // A sysvar shorter than 17 bytes has the condensed layout.
        Err(ProgramError::InvalidArgument) => {
            let mut condensed = [0u8; 8];
            get_sysvar(&mut condensed, &RENT_ID, 0)?;
            bytes
                .checked_mul(u64::from_le_bytes(condensed))
                .ok_or(ProgramError::ArithmeticOverflow)
        }
        Err(e) => Err(e),
    }
}

/// Settles rent so that after a resize to `new_len` the account holds
/// exactly the rent-exempt minimum. The payer funds growth through a system
/// transfer and receives the refund when the account shrinks.
pub fn settle_rent(
    did_account: &mut AccountView,
    payer: &mut AccountView,
    new_len: usize,
) -> Result<(), ProgramError> {
    let new_min = rent_minimum_balance(new_len)?;
    let current = did_account.lamports();
    if new_min > current {
        Transfer {
            from: payer,
            to: did_account,
            lamports: new_min - current,
        }
        .invoke()?;
    } else if new_min < current {
        let refund = current - new_min;
        did_account.set_lamports(new_min);
        let credited = payer
            .lamports()
            .checked_add(refund)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        payer.set_lamports(credited);
    }
    Ok(())
}

/// Grow the account by funding the new rent minimum, then extending the data.
pub fn grow(
    did_account: &mut AccountView,
    payer: &mut AccountView,
    new_len: usize,
) -> Result<(), ProgramError> {
    settle_rent(did_account, payer, new_len)?;
    did_account.resize(new_len)
}

/// Shrink the already compacted account by truncating it, then refunding.
pub fn shrink(
    did_account: &mut AccountView,
    payer: &mut AccountView,
    new_len: usize,
) -> Result<(), ProgramError> {
    did_account.resize(new_len)?;
    settle_rent(did_account, payer, new_len)
}

// ---------------------------------------------------------------------------
// Instruction-argument reads, kept for callers of earlier releases
// ---------------------------------------------------------------------------

#[deprecated(note = "use `reader::Reader`")]
#[inline(always)]
pub fn ix_read_bytes<'a>(
    data: &'a [u8],
    off: &mut usize,
    len: usize,
) -> Result<&'a [u8], ProgramError> {
    let mut r = Reader::<Args>::at(data, *off)?;
    let bytes = r.bytes(len)?;
    *off = r.offset();
    Ok(bytes)
}

#[deprecated(note = "use `reader::Reader`")]
#[inline(always)]
pub fn ix_read_u32(data: &[u8], off: &mut usize) -> Result<u32, ProgramError> {
    let mut r = Reader::<Args>::at(data, *off)?;
    let value = r.u32()?;
    *off = r.offset();
    Ok(value)
}

#[deprecated(note = "use `reader::Reader`")]
#[inline(always)]
pub fn ix_read_u16(data: &[u8], off: &mut usize) -> Result<u16, ProgramError> {
    let mut r = Reader::<Args>::at(data, *off)?;
    let value = r.u16()?;
    *off = r.offset();
    Ok(value)
}

#[deprecated(note = "use `reader::Reader`")]
#[inline(always)]
pub fn ix_read_u8(data: &[u8], off: &mut usize) -> Result<u8, ProgramError> {
    let mut r = Reader::<Args>::at(data, *off)?;
    let value = r.u8()?;
    *off = r.offset();
    Ok(value)
}

/// A borsh `Vec<u8>`, or the byte payload of a `String`.
#[deprecated(note = "use `reader::Reader`")]
#[inline(always)]
pub fn ix_read_len_prefixed<'a>(data: &'a [u8], off: &mut usize) -> Result<&'a [u8], ProgramError> {
    let mut r = Reader::<Args>::at(data, *off)?;
    let bytes = r.len_prefixed()?;
    *off = r.offset();
    Ok(bytes)
}

/// A borsh `String`, length-prefixed bytes that must be valid UTF-8.
#[deprecated(note = "use `reader::Reader`")]
#[inline(always)]
pub fn ix_read_str<'a>(data: &'a [u8], off: &mut usize) -> Result<&'a [u8], ProgramError> {
    let mut r = Reader::<Args>::at(data, *off)?;
    let bytes = r.str()?;
    *off = r.offset();
    Ok(bytes)
}

/// The arguments end where the last field ends. Bytes past it are a
/// malformed encoding, as they are for borsh's `try_from_slice`.
#[deprecated(note = "use `reader::Reader::finish`")]
#[inline(always)]
pub fn ix_finish(data: &[u8], off: usize) -> Result<(), ProgramError> {
    Reader::<Args>::at(data, off)?.finish()
}
