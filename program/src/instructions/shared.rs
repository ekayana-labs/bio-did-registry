//! Account validation and rent plumbing shared by the mutating instructions.
//!
//! ABI:
//!   realloc-family instructions: [payer, authority, did_account, system_program]
//!   set_verification_method_flags: [authority, did_account]
//!   initialize: [payer, did_account, system_program]

use pinocchio::{
    error::ProgramError,
    sysvars::{get_sysvar, rent::RENT_ID},
    AccountView, Address, Resize,
};
use pinocchio_system::instructions::Transfer;

use crate::state::{ACCOUNT_DISCRIMINATOR, BASE_SPACE, DID_SEED, OFF_BUMP, OFF_SUBJECT};

/// The payer funds rent growth and receives shrink refunds: signer + writable.
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

/// Loads an existing `DidAccount`: writable, owned by this program, carrying
/// the `DidAccount` discriminator, at the PDA ["bio-did", subject] with the
/// stored bump. Returns the subject key (needed for events).
pub fn verify_did_account(did_account: &AccountView) -> Result<[u8; 32], ProgramError> {
    if !did_account.is_writable() {
        return Err(ProgramError::Immutable);
    }
    if !did_account.owned_by(&crate::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let data = did_account.try_borrow()?;
    if data.len() < BASE_SPACE || data[0..8] != ACCOUNT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    let subject: [u8; 32] = data[OFF_SUBJECT..OFF_SUBJECT + 32].try_into().unwrap();
    let bump = data[OFF_BUMP];
    let expected = Address::create_program_address(&[DID_SEED, &subject, &[bump]], &crate::ID)
        .map_err(|_| ProgramError::InvalidSeeds)?;
    if did_account.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(subject)
}

/// Rent-exempt minimum for `data_len`, read from the rent sysvar.
///
/// Handles both sysvar layouts: the classic 17-byte
/// `{ lamports_per_byte_year: u64, exemption_threshold: f64, burn_percent: u8 }`
/// (current clusters) and the condensed 8-byte `{ lamports_per_byte: u64 }`
/// that `pinocchio::sysvars::rent::Rent` assumes. Relying on pinocchio's
/// `Rent::get()` alone under-funds by the exemption threshold (2x) on
/// classic-layout runtimes.
pub fn rent_minimum_balance(data_len: usize) -> Result<u64, ProgramError> {
    const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
    // f64 2.0 in little-endian IEEE-754; compared bitwise to avoid float ops
    // on the (universal) default-threshold path.
    const TWO_F64_LE: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0x40];

    let bytes = ACCOUNT_STORAGE_OVERHEAD
        .checked_add(data_len as u64)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let mut classic = [0u8; 17];
    match get_sysvar(&mut classic, &RENT_ID, 0) {
        Ok(()) => {
            let lamports_per_byte_year = u64::from_le_bytes(classic[0..8].try_into().unwrap());
            let base = bytes
                .checked_mul(lamports_per_byte_year)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            if classic[8..16] == TWO_F64_LE {
                base.checked_mul(2).ok_or(ProgramError::ArithmeticOverflow)
            } else {
                let threshold = f64::from_le_bytes(classic[8..16].try_into().unwrap());
                if !(threshold.is_finite() && threshold >= 0.0) {
                    return Err(ProgramError::InvalidArgument);
                }
                Ok((base as f64 * threshold) as u64)
            }
        }
        // Sysvar shorter than 17 bytes: the condensed layout.
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

/// Rent settlement: after a resize to `new_len`, the account holds exactly
/// the rent-exempt minimum - growth is funded by the payer (system
/// transfer), shrinkage is refunded to the payer.
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

/// Grow the account: fund the new rent minimum, then extend the data.
pub fn grow(
    did_account: &mut AccountView,
    payer: &mut AccountView,
    new_len: usize,
) -> Result<(), ProgramError> {
    settle_rent(did_account, payer, new_len)?;
    did_account.resize(new_len)
}

/// Shrink the account (data already compacted): truncate, then refund.
pub fn shrink(
    did_account: &mut AccountView,
    payer: &mut AccountView,
    new_len: usize,
) -> Result<(), ProgramError> {
    did_account.resize(new_len)?;
    settle_rent(did_account, payer, new_len)
}

// ---------------------------------------------------------------------------
// Instruction-argument cursor (borsh wire format, borrowed slices)
// ---------------------------------------------------------------------------

#[inline(always)]
pub fn ix_read_bytes<'a>(
    data: &'a [u8],
    off: &mut usize,
    len: usize,
) -> Result<&'a [u8], ProgramError> {
    let bytes = data
        .get(*off..*off + len)
        .ok_or(ProgramError::InvalidInstructionData)?;
    *off += len;
    Ok(bytes)
}

#[inline(always)]
pub fn ix_read_u32(data: &[u8], off: &mut usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(
        ix_read_bytes(data, off, 4)?.try_into().unwrap(),
    ))
}

#[inline(always)]
pub fn ix_read_u16(data: &[u8], off: &mut usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(
        ix_read_bytes(data, off, 2)?.try_into().unwrap(),
    ))
}

#[inline(always)]
pub fn ix_read_u8(data: &[u8], off: &mut usize) -> Result<u8, ProgramError> {
    Ok(ix_read_bytes(data, off, 1)?[0])
}

/// Borsh `Vec<u8>` / byte payload of a `String`.
#[inline(always)]
pub fn ix_read_len_prefixed<'a>(data: &'a [u8], off: &mut usize) -> Result<&'a [u8], ProgramError> {
    let len = ix_read_u32(data, off)? as usize;
    ix_read_bytes(data, off, len)
}

/// Borsh `String`: length-prefixed bytes that must be valid UTF-8 (borsh
/// enforces this; we replicate it so malformed args fail the same way).
#[inline(always)]
pub fn ix_read_str<'a>(data: &'a [u8], off: &mut usize) -> Result<&'a [u8], ProgramError> {
    let bytes = ix_read_len_prefixed(data, off)?;
    core::str::from_utf8(bytes).map_err(|_| ProgramError::InvalidInstructionData)?;
    Ok(bytes)
}
