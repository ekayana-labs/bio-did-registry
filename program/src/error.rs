//! Domain errors, surfaced as custom program error codes starting at 6000.
//! The numbering is part of the frozen wire format that clients rely on.

use pinocchio::error::ProgramError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DidError {
    /// Signer is not an authority for this DID
    Unauthorized = 6000,
    /// This DID has been permanently deactivated
    DidDeactivated = 6001,
    /// Fragment is empty, too long, or contains invalid characters
    InvalidFragment = 6002,
    /// A verification method or service with this fragment already exists
    FragmentAlreadyInUse = 6003,
    /// No verification method with this fragment exists
    VerificationMethodNotFound = 6004,
    /// No service with this fragment exists
    ServiceNotFound = 6005,
    /// Verification method limit reached
    TooManyVerificationMethods = 6006,
    /// Service limit reached
    TooManyServices = 6007,
    /// Controller limit reached
    TooManyControllers = 6008,
    /// Key material length does not match the verification method type
    InvalidKeyLength = 6009,
    /// Unknown flag bits, or flags not permitted for this key type
    InvalidFlags = 6010,
    /// Protected verification methods require their own key as authority
    ProtectedVerificationMethod = 6011,
    /// Operation would remove the last capable update authority
    LastAuthority = 6012,
    /// Controller entry is invalid or duplicated
    InvalidController = 6013,
    /// Service type or endpoint is empty, too long, or not printable ASCII
    InvalidServiceValue = 6014,
}

impl From<DidError> for ProgramError {
    #[inline(always)]
    fn from(e: DidError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

/// Early return a domain error unless `cond` holds.
#[inline(always)]
pub fn require(cond: bool, err: DidError) -> Result<(), ProgramError> {
    if cond {
        Ok(())
    } else {
        Err(err.into())
    }
}
