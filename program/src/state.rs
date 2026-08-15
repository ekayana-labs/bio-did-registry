//! Byte-level view of the `DidAccount` borsh layout.
//!
//! Layout (offsets from the start of account data), pinned by the golden
//! vectors in the test suite:
//!
//! ```text
//! 0   [u8; 8]  account discriminator sha256("account:DidAccount")[..8]
//! 8   u64      version (LE)
//! 16  u8       bump
//! 17  [u8;32]  subject
//! 49  u8       deactivated (0 | 1)
//! 50  i64      updated_at (LE)
//! 58  vec      native_controllers:   u32 count, then count * [u8; 32]
//! ..  vec      other_controllers:    u32 count, then count * (u32 len, bytes)
//! ..  vec      verification_methods: u32 count, then count * VM
//! ..  vec      services:             u32 count, then count * Service
//!
//! VM      = u32 fragment_len, fragment, u8 method_type, u16 flags (LE),
//!           u32 key_len, key
//! Service = u32 fragment_len, fragment, u32 type_len, type,
//!           u32 endpoint_len, endpoint
//! ```
//!
//! The program never deserializes this into owned structures; handlers edit
//! the buffer in place (`memmove` + patch) after computing spans with
//! [`Sections::parse`].

use pinocchio::error::ProgramError;

use crate::error::{require, DidError};

/// sha256("account:DidAccount")[..8] - written at initialize, checked on
/// every load.
pub const ACCOUNT_DISCRIMINATOR: [u8; 8] = [77, 88, 239, 141, 251, 29, 237, 243];

/// PDA seed prefix: ["bio-did", subject].
pub const DID_SEED: &[u8] = b"bio-did";

/// Reserved fragment for the subject's initial verification method.
pub const DEFAULT_FRAGMENT: &[u8] = b"default";

pub const MAX_VERIFICATION_METHODS: usize = 16;
pub const MAX_SERVICES: usize = 16;
pub const MAX_NATIVE_CONTROLLERS: usize = 8;
pub const MAX_OTHER_CONTROLLERS: usize = 8;
pub const MAX_FRAGMENT_LEN: usize = 32;
pub const MAX_SERVICE_TYPE_LEN: usize = 64;
pub const MAX_ENDPOINT_LEN: usize = 512;
pub const MAX_CONTROLLER_LEN: usize = 128;
pub const MAX_KEY_DATA_LEN: usize = 2592;

// Verification relationship / property bitflags (low five bits mirror the
// W3C DID verification relationships).
pub const VM_FLAG_AUTHENTICATION: u16 = 1 << 0;
pub const VM_FLAG_ASSERTION: u16 = 1 << 1;
pub const VM_FLAG_KEY_AGREEMENT: u16 = 1 << 2;
pub const VM_FLAG_CAPABILITY_INVOCATION: u16 = 1 << 3;
pub const VM_FLAG_CAPABILITY_DELEGATION: u16 = 1 << 4;
/// A protected method can only be removed, re-flagged, or newly added when
/// its own key signs as the transaction authority.
pub const VM_FLAG_PROTECTED: u16 = 1 << 8;

pub const VM_RELATIONSHIP_MASK: u16 = VM_FLAG_AUTHENTICATION
    | VM_FLAG_ASSERTION
    | VM_FLAG_KEY_AGREEMENT
    | VM_FLAG_CAPABILITY_INVOCATION
    | VM_FLAG_CAPABILITY_DELEGATION;

pub const VM_VALID_MASK: u16 = VM_RELATIONSHIP_MASK | VM_FLAG_PROTECTED;

/// All five relationships plus protection - assigned to the subject's
/// initial "default" verification method.
pub const VM_FLAGS_DEFAULT: u16 = VM_RELATIONSHIP_MASK | VM_FLAG_PROTECTED;

/// Verification method type tags (borsh enum discriminants).
pub const VM_TYPE_ED25519: u8 = 0;
pub const VM_TYPE_X25519: u8 = 1;
pub const VM_TYPE_SECP256K1: u8 = 2;
/// ML-DSA-87 (FIPS 204); the on-chain tag name predates the final standard.
pub const VM_TYPE_DILITHIUM5: u8 = 3;

/// Expected raw key length per method type; `None` for unknown tags.
#[inline]
pub fn expected_key_len(method_type: u8) -> Option<usize> {
    match method_type {
        VM_TYPE_ED25519 | VM_TYPE_X25519 => Some(32),
        VM_TYPE_SECP256K1 => Some(33),
        VM_TYPE_DILITHIUM5 => Some(2592),
        _ => None,
    }
}

// Fixed field offsets.
pub const OFF_VERSION: usize = 8;
pub const OFF_BUMP: usize = 16;
pub const OFF_SUBJECT: usize = 17;
pub const OFF_DEACTIVATED: usize = 49;
pub const OFF_UPDATED_AT: usize = 50;
/// Offset of the `native_controllers` count - the first vector section.
pub const OFF_SECTIONS: usize = 58;

/// Discriminator + scalars + the four vector length prefixes.
pub const BASE_SPACE: usize = 8 + 8 + 1 + 32 + 1 + 8 + 4 + 4 + 4 + 4;
/// The deactivated tombstone (all vectors empty).
pub const TOMBSTONE_SPACE: usize = BASE_SPACE;
/// A fresh account holding only the subject's "default" method.
pub const INITIAL_SPACE: usize = BASE_SPACE + 4 + DEFAULT_FRAGMENT.len() + 1 + 2 + 4 + 32;

/// Serialized size of one verification method entry.
#[inline(always)]
pub const fn vm_space(fragment_len: usize, key_len: usize) -> usize {
    4 + fragment_len + 1 + 2 + 4 + key_len
}

/// Serialized size of one service entry.
#[inline(always)]
pub const fn service_space(fragment_len: usize, type_len: usize, endpoint_len: usize) -> usize {
    4 + fragment_len + 4 + type_len + 4 + endpoint_len
}

// ---------------------------------------------------------------------------
// Bounds-checked cursor reads
// ---------------------------------------------------------------------------

#[inline(always)]
pub fn read_u32(data: &[u8], off: &mut usize) -> Result<u32, ProgramError> {
    let bytes: [u8; 4] = data
        .get(*off..*off + 4)
        .ok_or(ProgramError::InvalidAccountData)?
        .try_into()
        .unwrap();
    *off += 4;
    Ok(u32::from_le_bytes(bytes))
}

#[inline(always)]
pub fn read_bytes<'a>(
    data: &'a [u8],
    off: &mut usize,
    len: usize,
) -> Result<&'a [u8], ProgramError> {
    let bytes = data
        .get(*off..*off + len)
        .ok_or(ProgramError::InvalidAccountData)?;
    *off += len;
    Ok(bytes)
}

/// Reads a borsh `String`/`Vec<u8>`: u32 length prefix + payload.
#[inline(always)]
pub fn read_len_prefixed<'a>(data: &'a [u8], off: &mut usize) -> Result<&'a [u8], ProgramError> {
    let len = read_u32(data, off)? as usize;
    read_bytes(data, off, len)
}

// ---------------------------------------------------------------------------
// Section map
// ---------------------------------------------------------------------------

/// Offsets of the four vector sections inside the account data, computed by
/// a single bounds-checked walk. `*_count_pos` is the offset of the u32
/// count; `*_items` is the offset of the first item byte.
#[derive(Clone, Copy, Debug)]
pub struct Sections {
    pub nc_count: usize,
    pub nc_items: usize,
    pub oc_count: usize,
    pub oc_count_pos: usize,
    pub oc_items: usize,
    pub vm_count: usize,
    pub vm_count_pos: usize,
    pub vm_items: usize,
    pub svc_count: usize,
    pub svc_count_pos: usize,
    pub svc_items: usize,
    /// Total serialized size (== account data length for a healthy account).
    pub end: usize,
}

impl Sections {
    /// Walk the vector sections. Expects `data` to start at the account
    /// discriminator; the discriminator itself is checked by the caller.
    pub fn parse(data: &[u8]) -> Result<Self, ProgramError> {
        let mut off = OFF_SECTIONS;

        let nc_count = read_u32(data, &mut off)? as usize;
        let nc_items = off;
        read_bytes(data, &mut off, nc_count * 32)?;

        let oc_count_pos = off;
        let oc_count = read_u32(data, &mut off)? as usize;
        let oc_items = off;
        for _ in 0..oc_count {
            read_len_prefixed(data, &mut off)?;
        }

        let vm_count_pos = off;
        let vm_count = read_u32(data, &mut off)? as usize;
        let vm_items = off;
        for _ in 0..vm_count {
            read_len_prefixed(data, &mut off)?; // fragment
            read_bytes(data, &mut off, 1 + 2)?; // method_type + flags
            read_len_prefixed(data, &mut off)?; // key_data
        }

        let svc_count_pos = off;
        let svc_count = read_u32(data, &mut off)? as usize;
        let svc_items = off;
        for _ in 0..svc_count {
            read_len_prefixed(data, &mut off)?; // fragment
            read_len_prefixed(data, &mut off)?; // service_type
            read_len_prefixed(data, &mut off)?; // endpoint
        }

        Ok(Self {
            nc_count,
            nc_items,
            oc_count,
            oc_count_pos,
            oc_items,
            vm_count,
            vm_count_pos,
            vm_items,
            svc_count,
            svc_count_pos,
            svc_items,
            end: off,
        })
    }
}

/// A parsed verification method entry, borrowed from the account buffer.
#[derive(Clone, Copy, Debug)]
pub struct VmRef<'a> {
    pub fragment: &'a [u8],
    pub method_type: u8,
    pub flags: u16,
    pub key: &'a [u8],
    /// Byte span of the whole entry within the account data.
    pub start: usize,
    pub end: usize,
    /// Offset of the u16 flags field (for in-place patching).
    pub flags_pos: usize,
}

/// Iterate verification method entries. The buffer was validated by
/// [`Sections::parse`], but every read stays bounds-checked.
pub fn for_each_vm<'a>(
    data: &'a [u8],
    s: &Sections,
    mut f: impl FnMut(VmRef<'a>) -> Result<bool, ProgramError>,
) -> Result<(), ProgramError> {
    let mut off = s.vm_items;
    for _ in 0..s.vm_count {
        let start = off;
        let fragment = read_len_prefixed(data, &mut off)?;
        let method_type = read_bytes(data, &mut off, 1)?[0];
        let flags_pos = off;
        let flags = u16::from_le_bytes(read_bytes(data, &mut off, 2)?.try_into().unwrap());
        let key = read_len_prefixed(data, &mut off)?;
        let keep_going = f(VmRef {
            fragment,
            method_type,
            flags,
            key,
            start,
            end: off,
            flags_pos,
        })?;
        if !keep_going {
            break;
        }
    }
    Ok(())
}

/// A parsed service entry, borrowed from the account buffer.
#[derive(Clone, Copy, Debug)]
pub struct SvcRef<'a> {
    pub fragment: &'a [u8],
    pub start: usize,
    pub end: usize,
}

pub fn for_each_service<'a>(
    data: &'a [u8],
    s: &Sections,
    mut f: impl FnMut(SvcRef<'a>) -> Result<bool, ProgramError>,
) -> Result<(), ProgramError> {
    let mut off = s.svc_items;
    for _ in 0..s.svc_count {
        let start = off;
        let fragment = read_len_prefixed(data, &mut off)?;
        read_len_prefixed(data, &mut off)?; // service_type
        read_len_prefixed(data, &mut off)?; // endpoint
        let keep_going = f(SvcRef {
            fragment,
            start,
            end: off,
        })?;
        if !keep_going {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Domain checks
// ---------------------------------------------------------------------------

/// True when `signer` may mutate this DID: not deactivated, and the signer
/// matches an Ed25519 verification method carrying capabilityInvocation.
pub fn require_authority(data: &[u8], s: &Sections, signer: &[u8; 32]) -> Result<(), ProgramError> {
    require(data[OFF_DEACTIVATED] == 0, DidError::DidDeactivated)?;
    let mut authorized = false;
    for_each_vm(data, s, |vm| {
        if vm.method_type == VM_TYPE_ED25519
            && vm.flags & VM_FLAG_CAPABILITY_INVOCATION != 0
            && vm.key == signer
        {
            authorized = true;
            return Ok(false);
        }
        Ok(true)
    })?;
    require(authorized, DidError::Unauthorized)
}

/// Number of Ed25519 methods holding capabilityInvocation.
pub fn authority_count(data: &[u8], s: &Sections) -> Result<usize, ProgramError> {
    let mut n = 0usize;
    for_each_vm(data, s, |vm| {
        if vm.method_type == VM_TYPE_ED25519 && vm.flags & VM_FLAG_CAPABILITY_INVOCATION != 0 {
            n += 1;
        }
        Ok(true)
    })?;
    Ok(n)
}

/// Fragments are unique across verification methods AND services.
pub fn require_fragment_free(
    data: &[u8],
    s: &Sections,
    fragment: &[u8],
) -> Result<(), ProgramError> {
    let mut taken = false;
    for_each_vm(data, s, |vm| {
        if vm.fragment == fragment {
            taken = true;
            return Ok(false);
        }
        Ok(true)
    })?;
    if !taken {
        for_each_service(data, s, |svc| {
            if svc.fragment == fragment {
                taken = true;
                return Ok(false);
            }
            Ok(true)
        })?;
    }
    require(!taken, DidError::FragmentAlreadyInUse)
}

/// Flag sanity per key type:
/// - only known bits may be set;
/// - capabilityInvocation implies on-chain signing, so Ed25519 only;
/// - X25519 is a key-agreement key and cannot sign anything.
pub fn validate_vm_flags(method_type: u8, flags: u16) -> Result<(), ProgramError> {
    require(flags & !VM_VALID_MASK == 0, DidError::InvalidFlags)?;
    if flags & VM_FLAG_CAPABILITY_INVOCATION != 0 {
        require(method_type == VM_TYPE_ED25519, DidError::InvalidFlags)?;
    }
    if method_type == VM_TYPE_X25519 {
        require(
            flags & VM_RELATIONSHIP_MASK & !VM_FLAG_KEY_AGREEMENT == 0,
            DidError::InvalidFlags,
        )?;
    }
    Ok(())
}

/// Fragment charset: 1..=MAX_FRAGMENT_LEN of [A-Za-z0-9_-].
pub fn valid_fragment(fragment: &[u8]) -> bool {
    !fragment.is_empty()
        && fragment.len() <= MAX_FRAGMENT_LEN
        && fragment
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Printable ASCII (no whitespace), bounded length.
pub fn valid_uri_ascii(value: &[u8], max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && value.iter().all(|&b| (0x21..=0x7e).contains(&b))
}

/// Bump `version` (saturating) and stamp `updated_at`.
#[inline]
pub fn touch(data: &mut [u8], now: i64) {
    let version = u64::from_le_bytes(data[OFF_VERSION..OFF_VERSION + 8].try_into().unwrap());
    data[OFF_VERSION..OFF_VERSION + 8].copy_from_slice(&version.saturating_add(1).to_le_bytes());
    data[OFF_UPDATED_AT..OFF_UPDATED_AT + 8].copy_from_slice(&now.to_le_bytes());
}

/// Current `version` field.
#[inline]
pub fn version(data: &[u8]) -> u64 {
    u64::from_le_bytes(data[OFF_VERSION..OFF_VERSION + 8].try_into().unwrap())
}
