//! Events, emitted through the `sol_log_data` syscall: an 8-byte event
//! discriminator (sha256("event:<Name>")[..8]) followed by the
//! borsh-encoded fields, so indexers can subscribe via `Program data:` logs.
//!
//! All three events share the same body: `{ did_account, subject, version }`.

use pinocchio::Address;

pub const DID_INITIALIZED: [u8; 8] = [125, 40, 26, 220, 241, 180, 151, 84];
pub const DID_MODIFIED: [u8; 8] = [127, 241, 158, 225, 33, 224, 88, 208];
pub const DID_DEACTIVATED: [u8; 8] = [6, 124, 31, 30, 191, 92, 197, 57];

/// Emit one event: discriminator + did_account + subject + version.
pub fn emit(discriminator: &[u8; 8], did_account: &Address, subject: &[u8; 32], version: u64) {
    let mut buf = [0u8; 80];
    buf[0..8].copy_from_slice(discriminator);
    buf[8..40].copy_from_slice(did_account.as_ref());
    buf[40..72].copy_from_slice(subject);
    buf[72..80].copy_from_slice(&version.to_le_bytes());
    log_data(&buf);
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline]
fn log_data(bytes: &[u8]) {
    // The syscall takes a pointer to an array of `&[u8]` fat pointers.
    let slices: &[&[u8]] = &[bytes];
    unsafe {
        pinocchio::syscalls::sol_log_data(slices.as_ptr() as *const u8, slices.len() as u64);
    }
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline]
fn log_data(_bytes: &[u8]) {}
