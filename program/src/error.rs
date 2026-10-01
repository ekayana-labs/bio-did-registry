//! Domain errors, surfaced as custom program error codes starting at 6000.
//! The numbering is part of the frozen wire format that clients rely on,
//! and new codes are only ever appended.

use pinocchio::error::ProgramError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DidError {
    /// Signer is not an authority for this DID
    Unauthorized = 6000,
    /// This DID has been permanently deactivated
    DidDeactivated = 6001,
    /// Fragment is empty, too long, reserved, or contains invalid characters
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
    /// Key buffer is not bound to this DID and authority
    InvalidKeyBuffer = 6015,
    /// Chunk does not continue the bytes written so far, or runs past the key length
    InvalidKeyChunk = 6016,
    /// Key buffer has not received every byte of the key yet
    KeyBufferIncomplete = 6017,
    /// Key material is not a valid public key for the verification method type
    InvalidKey = 6018,
}

impl DidError {
    /// Every error, in code order from 6000.
    pub const ALL: &'static [DidError] = &[
        DidError::Unauthorized,
        DidError::DidDeactivated,
        DidError::InvalidFragment,
        DidError::FragmentAlreadyInUse,
        DidError::VerificationMethodNotFound,
        DidError::ServiceNotFound,
        DidError::TooManyVerificationMethods,
        DidError::TooManyServices,
        DidError::TooManyControllers,
        DidError::InvalidKeyLength,
        DidError::InvalidFlags,
        DidError::ProtectedVerificationMethod,
        DidError::LastAuthority,
        DidError::InvalidController,
        DidError::InvalidServiceValue,
        DidError::InvalidKeyBuffer,
        DidError::InvalidKeyChunk,
        DidError::KeyBufferIncomplete,
        DidError::InvalidKey,
    ];

    /// The custom program error code.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// The error behind a custom program error code, if the code is one of
    /// this program's.
    pub fn from_code(code: u32) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.code() == code)
    }

    /// What the error means, in the words of its documentation.
    pub const fn message(self) -> &'static str {
        match self {
            DidError::Unauthorized => "Signer is not an authority for this DID",
            DidError::DidDeactivated => "This DID has been permanently deactivated",
            DidError::InvalidFragment => {
                "Fragment is empty, too long, reserved, or contains invalid characters"
            }
            DidError::FragmentAlreadyInUse => {
                "A verification method or service with this fragment already exists"
            }
            DidError::VerificationMethodNotFound => {
                "No verification method with this fragment exists"
            }
            DidError::ServiceNotFound => "No service with this fragment exists",
            DidError::TooManyVerificationMethods => "Verification method limit reached",
            DidError::TooManyServices => "Service limit reached",
            DidError::TooManyControllers => "Controller limit reached",
            DidError::InvalidKeyLength => {
                "Key material length does not match the verification method type"
            }
            DidError::InvalidFlags => "Unknown flag bits, or flags not permitted for this key type",
            DidError::ProtectedVerificationMethod => {
                "Protected verification methods require their own key as authority"
            }
            DidError::LastAuthority => "Operation would remove the last capable update authority",
            DidError::InvalidController => "Controller entry is invalid or duplicated",
            DidError::InvalidServiceValue => {
                "Service type or endpoint is empty, too long, or not printable ASCII"
            }
            DidError::InvalidKeyBuffer => "Key buffer is not bound to this DID and authority",
            DidError::InvalidKeyChunk => {
                "Chunk does not continue the bytes written so far, or runs past the key length"
            }
            DidError::KeyBufferIncomplete => {
                "Key buffer has not received every byte of the key yet"
            }
            DidError::InvalidKey => {
                "Key material is not a valid public key for the verification method type"
            }
        }
    }
}

impl TryFrom<u32> for DidError {
    /// The code, when it is not one of this program's.
    type Error = u32;

    fn try_from(code: u32) -> Result<Self, u32> {
        Self::from_code(code).ok_or(code)
    }
}

impl core::fmt::Display for DidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl core::error::Error for DidError {}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_run_from_6000_without_gaps() {
        for (i, e) in DidError::ALL.iter().enumerate() {
            assert_eq!(e.code(), 6000 + i as u32);
            assert_eq!(DidError::from_code(e.code()), Some(*e));
            assert_eq!(DidError::try_from(e.code()), Ok(*e));
            assert_eq!(ProgramError::from(*e), ProgramError::Custom(e.code()));
            assert!(!e.message().is_empty());
        }
        let next = 6000 + DidError::ALL.len() as u32;
        assert_eq!(DidError::from_code(next), None);
        assert_eq!(DidError::try_from(5999), Err(5999));
        assert_eq!(
            DidError::InvalidKey.to_string(),
            "Key material is not a valid public key for the verification method type"
        );
    }
}
