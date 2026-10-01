//! Byte-level view of the `DidAccount` borsh layout.
//!
//! The golden vectors in the test suite pin this layout. Offsets count from
//! the start of the account data.
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
//! The program never deserializes this into owned structures. Handlers
//! compute spans with [`Sections::parse`], then move and patch the bytes in
//! place.

use core::mem::{offset_of, size_of};

use pinocchio::error::ProgramError;

use crate::error::{require, DidError};
use crate::reader::{Account, Reader};

/// sha256("account:DidAccount")[..8], written at initialize and checked on
/// every load.
pub const ACCOUNT_DISCRIMINATOR: [u8; 8] = [77, 88, 239, 141, 251, 29, 237, 243];

/// PDA seed prefix. The seeds are ["bio-did", subject].
pub const DID_SEED: &[u8] = b"bio-did";

/// Seed prefix of an owned subject, which the program derives as
/// `find_program_address(["bio-did-owned", authority, nonce_le])`.
pub const OWNED_SUBJECT_SEED: &[u8] = b"bio-did-owned";

/// The seeds of the owned subject for `authority` and `nonce`, in the order
/// `find_program_address` expects them.
#[inline(always)]
pub fn owned_subject_seeds<'a>(authority: &'a [u8; 32], nonce: &'a [u8; 8]) -> [&'a [u8]; 3] {
    [OWNED_SUBJECT_SEED, authority, nonce]
}

/// The owned subject that `initialize_owned(nonce)` signed by `authority`
/// creates. The address is off the curve, so the DID resolves only through
/// the registry.
pub fn owned_subject(authority: &[u8; 32], nonce: u64) -> [u8; 32] {
    let nonce = nonce.to_le_bytes();
    let (subject, _) = pinocchio::Address::find_program_address(
        &owned_subject_seeds(authority, &nonce),
        &crate::ID,
    );
    *subject.as_array()
}

/// The fragment of the founding verification method. `initialize` and
/// `initialize_owned` write it and no instruction accepts it, so once that
/// method is gone, `#default` stays gone.
pub const DEFAULT_FRAGMENT: &[u8] = b"default";

pub const MAX_VERIFICATION_METHODS: usize = 16;
pub const MAX_SERVICES: usize = 16;
pub const MAX_NATIVE_CONTROLLERS: usize = 8;
pub const MAX_OTHER_CONTROLLERS: usize = 8;
pub const MAX_FRAGMENT_LEN: usize = 32;
pub const MAX_SERVICE_TYPE_LEN: usize = 64;
pub const MAX_ENDPOINT_LEN: usize = 512;
pub const MAX_CONTROLLER_LEN: usize = 128;
#[deprecated(
    since = "0.1.2",
    note = "the program never reads it, and expected_key_len fixes key lengths per type"
)]
pub const MAX_KEY_DATA_LEN: usize = 2592;

// Verification relationship and property bitflags. The low five bits mirror
// the W3C DID verification relationships.
pub const VM_FLAG_AUTHENTICATION: u16 = 1 << 0;
pub const VM_FLAG_ASSERTION: u16 = 1 << 1;
pub const VM_FLAG_KEY_AGREEMENT: u16 = 1 << 2;
pub const VM_FLAG_CAPABILITY_INVOCATION: u16 = 1 << 3;
pub const VM_FLAG_CAPABILITY_DELEGATION: u16 = 1 << 4;
/// A protected method can only be removed, re-flagged, or newly added when
/// its own key signs as the transaction authority. It keeps
/// capabilityInvocation, so that key can always act on it.
pub const VM_FLAG_PROTECTED: u16 = 1 << 8;

pub const VM_RELATIONSHIP_MASK: u16 = VM_FLAG_AUTHENTICATION
    | VM_FLAG_ASSERTION
    | VM_FLAG_KEY_AGREEMENT
    | VM_FLAG_CAPABILITY_INVOCATION
    | VM_FLAG_CAPABILITY_DELEGATION;

pub const VM_VALID_MASK: u16 = VM_RELATIONSHIP_MASK | VM_FLAG_PROTECTED;

/// All five relationships plus protection, assigned to the subject's
/// initial "default" verification method.
pub const VM_FLAGS_DEFAULT: u16 = VM_RELATIONSHIP_MASK | VM_FLAG_PROTECTED;

/// Verification method type tags, the borsh enum discriminants.
pub const VM_TYPE_ED25519: u8 = 0;
pub const VM_TYPE_X25519: u8 = 1;
pub const VM_TYPE_SECP256K1: u8 = 2;
/// ML-DSA-87 (FIPS 204). The on-chain tag name predates the final standard.
pub const VM_TYPE_DILITHIUM5: u8 = 3;

/// Expected raw key length per method type, or `None` for unknown tags.
#[inline]
pub fn expected_key_len(method_type: u8) -> Option<usize> {
    match method_type {
        VM_TYPE_ED25519 | VM_TYPE_X25519 => Some(32),
        VM_TYPE_SECP256K1 => Some(33),
        VM_TYPE_DILITHIUM5 => Some(2592),
        _ => None,
    }
}

/// The fixed head of a `DidAccount`, before the vector sections. Every
/// field is a byte array, so the struct has no padding and its field
/// offsets are the account layout's.
#[repr(C)]
pub struct DidAccountHeader {
    pub discriminator: [u8; 8],
    pub version: [u8; 8],
    pub bump: u8,
    pub subject: [u8; 32],
    pub deactivated: u8,
    pub updated_at: [u8; 8],
}

// Fixed field offsets.
pub const OFF_VERSION: usize = offset_of!(DidAccountHeader, version);
pub const OFF_BUMP: usize = offset_of!(DidAccountHeader, bump);
pub const OFF_SUBJECT: usize = offset_of!(DidAccountHeader, subject);
pub const OFF_DEACTIVATED: usize = offset_of!(DidAccountHeader, deactivated);
pub const OFF_UPDATED_AT: usize = offset_of!(DidAccountHeader, updated_at);
/// Offset of the `native_controllers` count, the first vector section.
pub const OFF_SECTIONS: usize = size_of::<DidAccountHeader>();

/// The discriminator, the scalars and the four vector length prefixes.
pub const BASE_SPACE: usize = OFF_SECTIONS + 4 * 4;
/// The deactivated tombstone, with all vectors empty.
pub const TOMBSTONE_SPACE: usize = BASE_SPACE;
/// A fresh account holding only the subject's "default" method.
pub const INITIAL_SPACE: usize = BASE_SPACE + vm_space(DEFAULT_FRAGMENT.len(), 32);

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
// Key buffer, the staging account for keys larger than one transaction
// ---------------------------------------------------------------------------
//
// A 2592 byte ML-DSA-87 key cannot travel in a single 1232 byte transaction,
// so it is uploaded in chunks into a `KeyBuffer` PDA and then appended to
// the DID account by `add_verification_method_from_buffer`. The layout follows.
//
// ```text
// 0    [u8; 8]  discriminator sha256("account:KeyBuffer")[..8]
// 8    [u8;32]  did_account   the DID this key is destined for
// 40   [u8;32]  authority     the only key allowed to write, finish, or close
// 72   u8       bump
// 73   u8       method_type
// 74   u16      flags (LE)
// 76   u32      key_len (LE)  total key length, fixed at creation
// 80   u32      written (LE)  bytes received so far, always a prefix
// 84   u32      fragment_len (LE)
// 88   [u8;32]  fragment, zero padded
// 120  [u8]     key bytes (key_len)
// ```

/// sha256("account:KeyBuffer")[..8].
pub const KEY_BUFFER_DISCRIMINATOR: [u8; 8] = [150, 138, 44, 35, 255, 159, 45, 0];

/// PDA seed prefix. The seeds are ["bio-did-key", did_account, authority].
pub const KEY_BUFFER_SEED: &[u8] = b"bio-did-key";

/// The fixed header of a `KeyBuffer`, which the key bytes follow. Like
/// [`DidAccountHeader`] it is all byte arrays, so its offsets are the
/// account layout's.
#[repr(C)]
pub struct KeyBufferHeader {
    pub discriminator: [u8; 8],
    pub did_account: [u8; 32],
    pub authority: [u8; 32],
    pub bump: u8,
    pub method_type: u8,
    pub flags: [u8; 2],
    pub key_len: [u8; 4],
    pub written: [u8; 4],
    pub fragment_len: [u8; 4],
    pub fragment: [u8; MAX_FRAGMENT_LEN],
}

pub const KB_OFF_DID_ACCOUNT: usize = offset_of!(KeyBufferHeader, did_account);
pub const KB_OFF_AUTHORITY: usize = offset_of!(KeyBufferHeader, authority);
pub const KB_OFF_BUMP: usize = offset_of!(KeyBufferHeader, bump);
pub const KB_OFF_METHOD_TYPE: usize = offset_of!(KeyBufferHeader, method_type);
pub const KB_OFF_FLAGS: usize = offset_of!(KeyBufferHeader, flags);
pub const KB_OFF_KEY_LEN: usize = offset_of!(KeyBufferHeader, key_len);
pub const KB_OFF_WRITTEN: usize = offset_of!(KeyBufferHeader, written);
pub const KB_OFF_FRAGMENT_LEN: usize = offset_of!(KeyBufferHeader, fragment_len);
pub const KB_OFF_FRAGMENT: usize = offset_of!(KeyBufferHeader, fragment);
/// Offset of the key bytes, which is also the fixed header size.
pub const KB_OFF_KEY: usize = size_of::<KeyBufferHeader>();
pub const KEY_BUFFER_HEADER: usize = KB_OFF_KEY;

// The wire format is frozen, so a field that moves fails the build.
const _: () = {
    assert!(OFF_VERSION == 8);
    assert!(OFF_BUMP == 16);
    assert!(OFF_SUBJECT == 17);
    assert!(OFF_DEACTIVATED == 49);
    assert!(OFF_UPDATED_AT == 50);
    assert!(OFF_SECTIONS == 58);
    assert!(BASE_SPACE == 74);
    assert!(INITIAL_SPACE == 124);
    assert!(KB_OFF_DID_ACCOUNT == 8);
    assert!(KB_OFF_AUTHORITY == 40);
    assert!(KB_OFF_BUMP == 72);
    assert!(KB_OFF_METHOD_TYPE == 73);
    assert!(KB_OFF_FLAGS == 74);
    assert!(KB_OFF_KEY_LEN == 76);
    assert!(KB_OFF_WRITTEN == 80);
    assert!(KB_OFF_FRAGMENT_LEN == 84);
    assert!(KB_OFF_FRAGMENT == 88);
    assert!(KEY_BUFFER_HEADER == 120);
};

/// A parsed key buffer header, borrowed from the account buffer.
#[derive(Clone, Copy, Debug)]
pub struct KeyBufferRef<'a> {
    pub did_account: &'a [u8],
    pub authority: &'a [u8],
    pub bump: u8,
    pub method_type: u8,
    pub flags: u16,
    pub key_len: usize,
    pub written: usize,
    pub fragment: &'a [u8],
}

impl<'a> KeyBufferRef<'a> {
    /// Read the header of a buffer whose discriminator was already checked.
    /// The data length must match the declared key length exactly.
    pub fn parse(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (header, key) = data
            .split_first_chunk::<KEY_BUFFER_HEADER>()
            .ok_or(ProgramError::InvalidAccountData)?;
        let mut r = Reader::<Account>::at(header, KB_OFF_DID_ACCOUNT)?;
        let did_account = r.array::<32>()?;
        let authority = r.array::<32>()?;
        let bump = r.u8()?;
        let method_type = r.u8()?;
        let flags = r.u16()?;
        let key_len = r.u32()? as usize;
        let written = r.u32()? as usize;
        let fragment_len = r.u32()? as usize;
        let fragment = r.array::<MAX_FRAGMENT_LEN>()?;
        if key.len() != key_len || written > key_len || fragment_len > MAX_FRAGMENT_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(Self {
            did_account,
            authority,
            bump,
            method_type,
            flags,
            key_len,
            written,
            fragment: &fragment[..fragment_len],
        })
    }

    /// The key bytes received so far.
    pub fn key(&self, data: &'a [u8]) -> &'a [u8] {
        &data[KB_OFF_KEY..KB_OFF_KEY + self.written]
    }
}

// ---------------------------------------------------------------------------
// Bounds-checked offset reads, kept for callers of earlier releases
// ---------------------------------------------------------------------------

#[deprecated(note = "use `reader::Reader`")]
#[inline(always)]
pub fn read_u32(data: &[u8], off: &mut usize) -> Result<u32, ProgramError> {
    let mut r = Reader::<Account>::at(data, *off)?;
    let value = r.u32()?;
    *off = r.offset();
    Ok(value)
}

#[deprecated(note = "use `reader::Reader`")]
#[inline(always)]
pub fn read_bytes<'a>(
    data: &'a [u8],
    off: &mut usize,
    len: usize,
) -> Result<&'a [u8], ProgramError> {
    let mut r = Reader::<Account>::at(data, *off)?;
    let bytes = r.bytes(len)?;
    *off = r.offset();
    Ok(bytes)
}

/// Reads a borsh `String` or `Vec<u8>`, a u32 length prefix and then the payload.
#[deprecated(note = "use `reader::Reader`")]
#[inline(always)]
pub fn read_len_prefixed<'a>(data: &'a [u8], off: &mut usize) -> Result<&'a [u8], ProgramError> {
    let mut r = Reader::<Account>::at(data, *off)?;
    let bytes = r.len_prefixed()?;
    *off = r.offset();
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Section map
// ---------------------------------------------------------------------------

/// Offsets of the four vector sections inside the account data, computed by
/// a single bounds-checked walk. `*_count_pos` is the offset of the u32
/// count, and `*_items` is the offset of the first item byte.
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
    /// Total serialized size. It always equals the account data length,
    /// since [`Sections::parse`] rejects anything shorter or longer.
    pub end: usize,
}

impl Sections {
    /// Walk the vector sections. `data` is the whole account data, starting
    /// at the discriminator, which the caller has checked. The layout must
    /// account for every byte, so handlers can treat `end` as the account
    /// length when they move the tail.
    pub fn parse(data: &[u8]) -> Result<Self, ProgramError> {
        let mut r = Reader::<Account>::at(data, OFF_SECTIONS)?;

        let nc_count = r.u32()? as usize;
        let nc_items = r.offset();
        r.bytes(nc_count * 32)?;

        let oc_count_pos = r.offset();
        let oc_count = r.u32()? as usize;
        let oc_items = r.offset();
        for _ in 0..oc_count {
            r.len_prefixed()?;
        }

        let vm_count_pos = r.offset();
        let vm_count = r.u32()? as usize;
        let vm_items = r.offset();
        for _ in 0..vm_count {
            r.len_prefixed()?; // fragment
            r.bytes(1 + 2)?; // method_type + flags
            r.len_prefixed()?; // key_data
        }

        let svc_count_pos = r.offset();
        let svc_count = r.u32()? as usize;
        let svc_items = r.offset();
        for _ in 0..svc_count {
            r.len_prefixed()?; // fragment
            r.len_prefixed()?; // service_type
            r.len_prefixed()?; // endpoint
        }
        let end = r.offset();
        r.finish()?;

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
            end,
        })
    }
}

/// A `DidAccount` whose layout [`Sections::parse`] accepted, borrowed from
/// the account data. The section offsets come from these exact bytes, so a
/// view never pairs a layout with a different buffer.
#[derive(Clone, Copy, Debug)]
pub struct DidView<'a> {
    data: &'a [u8],
    sections: Sections,
}

// The lookups below loop by hand. `Iterator::find` and `any` go through
// `try_fold`, which SBF builds do not inline, and that costs CU on every call.
impl<'a> DidView<'a> {
    /// Parse the whole account data, starting at the discriminator, which
    /// the caller has checked.
    #[inline(always)]
    pub fn parse(data: &'a [u8]) -> Result<Self, ProgramError> {
        Ok(Self {
            data,
            sections: Sections::parse(data)?,
        })
    }

    #[inline(always)]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    #[inline(always)]
    pub const fn sections(&self) -> &Sections {
        &self.sections
    }

    #[inline(always)]
    pub fn is_deactivated(&self) -> bool {
        self.data[OFF_DEACTIVATED] != 0
    }

    /// The verification method entries in storage order.
    #[inline(always)]
    pub fn vms(&self) -> VmIter<'a> {
        let s = &self.sections;
        VmIter {
            reader: section(self.data, s.vm_items, s.svc_count_pos),
        }
    }

    /// The service entries in storage order.
    #[inline(always)]
    pub fn services(&self) -> SvcIter<'a> {
        let s = &self.sections;
        SvcIter {
            reader: section(self.data, s.svc_items, s.end),
        }
    }

    /// The verification method named `fragment`.
    #[inline(always)]
    #[allow(clippy::manual_find)]
    pub fn find_vm(&self, fragment: &[u8]) -> Option<VmRef<'a>> {
        for vm in self.vms() {
            if vm.fragment == fragment {
                return Some(vm);
            }
        }
        None
    }

    /// The service named `fragment`.
    #[inline(always)]
    #[allow(clippy::manual_find)]
    pub fn find_service(&self, fragment: &[u8]) -> Option<SvcRef<'a>> {
        for svc in self.services() {
            if svc.fragment == fragment {
                return Some(svc);
            }
        }
        None
    }

    /// True when `signer` holds an Ed25519 method with capabilityInvocation.
    #[inline(always)]
    pub fn is_authority(&self, signer: &[u8; 32]) -> bool {
        for vm in self.vms() {
            if vm.is_authority() && vm.key == signer {
                return true;
            }
        }
        false
    }

    /// Checks that `signer` may mutate this DID. It must not be deactivated,
    /// and the signer must be one of its authorities.
    #[inline(never)]
    pub fn require_authority(&self, signer: &[u8; 32]) -> Result<(), ProgramError> {
        require(!self.is_deactivated(), DidError::DidDeactivated)?;
        require(self.is_authority(signer), DidError::Unauthorized)
    }

    /// Number of Ed25519 methods holding capabilityInvocation.
    #[inline(never)]
    pub fn authority_count(&self) -> usize {
        let mut n = 0;
        for vm in self.vms() {
            if vm.is_authority() {
                n += 1;
            }
        }
        n
    }

    /// Fragments are unique across verification methods and services
    /// together, and `#default` belongs to the founding method alone.
    #[inline(never)]
    pub fn require_fragment_free(&self, fragment: &[u8]) -> Result<(), ProgramError> {
        let taken = self.find_vm(fragment).is_some() || self.find_service(fragment).is_some();
        require(!taken, DidError::FragmentAlreadyInUse)?;
        require(fragment != DEFAULT_FRAGMENT, DidError::InvalidFragment)
    }

    /// The rules a new verification method must pass against the document
    /// as it is now, in the order every path that adds one reports them.
    /// The key bytes are checked by [`check_new_key`] once they are known.
    #[inline(always)]
    pub fn check_new_method(&self, signer: &[u8; 32], m: &NewMethod) -> Result<(), ProgramError> {
        self.require_authority(signer)?;
        require(
            self.sections.vm_count < MAX_VERIFICATION_METHODS,
            DidError::TooManyVerificationMethods,
        )?;
        require(valid_fragment(m.fragment), DidError::InvalidFragment)?;
        self.require_fragment_free(m.fragment)?;
        require(
            expected_key_len(m.method_type) == Some(m.key_len),
            DidError::InvalidKeyLength,
        )?;
        validate_vm_flags(m.method_type, m.flags)
    }
}

/// A verification method on its way into a document, described without its
/// key bytes, which may still sit in a key buffer.
#[derive(Clone, Copy, Debug)]
pub struct NewMethod<'a> {
    pub fragment: &'a [u8],
    pub method_type: u8,
    pub flags: u16,
    pub key_len: usize,
}

/// The rules a new method's key bytes must pass.
///
/// - A method may only be born protected if it belongs to the signer, so no
///   co-authority can plant an unremovable key.
/// - An Ed25519 key must be a curve point. An address off the curve has no
///   private key, and only a program can sign for it, through a CPI, so it
///   enters only as the signer itself.
/// - A secp256k1 key is a compressed SEC1 point, which starts with 0x02 or
///   0x03.
#[inline(always)]
pub fn check_new_key(m: &NewMethod, key: &[u8], signer: &[u8; 32]) -> Result<(), ProgramError> {
    if m.flags & VM_FLAG_PROTECTED != 0 {
        require(key == signer, DidError::ProtectedVerificationMethod)?;
    }
    match m.method_type {
        VM_TYPE_ED25519 => require(
            key == signer || pinocchio::address::bytes_are_curve_point(key),
            DidError::InvalidKey,
        ),
        VM_TYPE_SECP256K1 => require(
            matches!(key.first(), Some(0x02 | 0x03)),
            DidError::InvalidKey,
        ),
        _ => Ok(()),
    }
}

/// Appends a verification method entry to a document whose data has already
/// grown by the entry's size. `s` is the layout from before the growth. The
/// services move right to make room, and the method count goes up by one.
#[inline(always)]
pub fn insert_vm(data: &mut [u8], s: &Sections, m: &NewMethod, key: &[u8]) {
    let at = s.svc_count_pos;
    let entry_len = vm_space(m.fragment.len(), key.len());
    data.copy_within(at..s.end, at + entry_len);
    let mut w = at;
    data[w..w + 4].copy_from_slice(&(m.fragment.len() as u32).to_le_bytes());
    w += 4;
    data[w..w + m.fragment.len()].copy_from_slice(m.fragment);
    w += m.fragment.len();
    data[w] = m.method_type;
    w += 1;
    data[w..w + 2].copy_from_slice(&m.flags.to_le_bytes());
    w += 2;
    data[w..w + 4].copy_from_slice(&(key.len() as u32).to_le_bytes());
    w += 4;
    data[w..w + key.len()].copy_from_slice(key);
    data[s.vm_count_pos..s.vm_count_pos + 4]
        .copy_from_slice(&((s.vm_count + 1) as u32).to_le_bytes());
}

/// A cursor over the entries of one section, which ends where the next
/// section's count begins. Offsets stay relative to the account data.
#[inline(always)]
fn section(data: &[u8], items: usize, end: usize) -> Reader<'_, Account> {
    match data.get(..end) {
        Some(head) => Reader::at(head, items).unwrap_or(Reader::new(&[])),
        None => Reader::new(&[]),
    }
}

/// Walks verification method entries. Over a [`DidView`] every entry reads
/// back, since [`Sections::parse`] walked the same bytes.
#[derive(Clone, Copy, Debug)]
pub struct VmIter<'a> {
    reader: Reader<'a, Account>,
}

impl<'a> Iterator for VmIter<'a> {
    type Item = VmRef<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<VmRef<'a>> {
        let r = &mut self.reader;
        if r.remaining().is_empty() {
            return None;
        }
        let start = r.offset();
        let fragment = r.len_prefixed().ok()?;
        let method_type = r.u8().ok()?;
        let flags_pos = r.offset();
        let flags = r.u16().ok()?;
        let key = r.len_prefixed().ok()?;
        Some(VmRef {
            fragment,
            method_type,
            flags,
            key,
            start,
            end: r.offset(),
            flags_pos,
        })
    }
}

/// Walks service entries, like [`VmIter`].
#[derive(Clone, Copy, Debug)]
pub struct SvcIter<'a> {
    reader: Reader<'a, Account>,
}

impl<'a> Iterator for SvcIter<'a> {
    type Item = SvcRef<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<SvcRef<'a>> {
        let r = &mut self.reader;
        if r.remaining().is_empty() {
            return None;
        }
        let start = r.offset();
        let fragment = r.len_prefixed().ok()?;
        r.len_prefixed().ok()?; // service_type
        r.len_prefixed().ok()?; // endpoint
        Some(SvcRef {
            fragment,
            start,
            end: r.offset(),
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
    /// Offset of the u16 flags field, used for in-place patching.
    pub flags_pos: usize,
}

impl VmRef<'_> {
    /// True for an Ed25519 method holding capabilityInvocation, the kind of
    /// method that may sign updates.
    #[inline(always)]
    pub fn is_authority(&self) -> bool {
        self.method_type == VM_TYPE_ED25519 && self.flags & VM_FLAG_CAPABILITY_INVOCATION != 0
    }
}

/// Iterate verification method entries. The buffer was validated by
/// [`Sections::parse`], but every read stays bounds-checked.
#[deprecated(note = "use `DidView::vms`")]
pub fn for_each_vm<'a>(
    data: &'a [u8],
    s: &Sections,
    mut f: impl FnMut(VmRef<'a>) -> Result<bool, ProgramError>,
) -> Result<(), ProgramError> {
    let mut r = Reader::<Account>::at(data, s.vm_items)?;
    for _ in 0..s.vm_count {
        let start = r.offset();
        let fragment = r.len_prefixed()?;
        let method_type = r.u8()?;
        let flags_pos = r.offset();
        let flags = r.u16()?;
        let key = r.len_prefixed()?;
        let keep_going = f(VmRef {
            fragment,
            method_type,
            flags,
            key,
            start,
            end: r.offset(),
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

/// Iterate service entries, bounds-checked like [`for_each_vm`].
#[deprecated(note = "use `DidView::services`")]
pub fn for_each_service<'a>(
    data: &'a [u8],
    s: &Sections,
    mut f: impl FnMut(SvcRef<'a>) -> Result<bool, ProgramError>,
) -> Result<(), ProgramError> {
    let mut r = Reader::<Account>::at(data, s.svc_items)?;
    for _ in 0..s.svc_count {
        let start = r.offset();
        let fragment = r.len_prefixed()?;
        r.len_prefixed()?; // service_type
        r.len_prefixed()?; // endpoint
        let keep_going = f(SvcRef {
            fragment,
            start,
            end: r.offset(),
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

/// Checks that `signer` may mutate this DID. It must not be deactivated, and the
/// signer must match an Ed25519 verification method carrying capabilityInvocation.
#[deprecated(note = "use `DidView::require_authority`")]
#[allow(deprecated)]
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
#[deprecated(note = "use `DidView::authority_count`")]
#[allow(deprecated)]
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

/// Fragments are unique across verification methods and services together,
/// and `#default` belongs to the founding method alone.
#[deprecated(note = "use `DidView::require_fragment_free`")]
#[allow(deprecated)]
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
    require(!taken, DidError::FragmentAlreadyInUse)?;
    require(fragment != DEFAULT_FRAGMENT, DidError::InvalidFragment)
}

/// Checks the flags against the key type.
/// - Only known bits may be set.
/// - capabilityInvocation implies on-chain signing, so it is Ed25519 only.
/// - Protection is proven by the method's own key signing a transaction,
///   so it is Ed25519 only as well, and it needs capabilityInvocation. A
///   protected method without it could never be changed or removed again.
/// - X25519 is a key-agreement key and cannot sign anything.
/// - ML-DSA-87 is a signature scheme with no key agreement.
pub fn validate_vm_flags(method_type: u8, flags: u16) -> Result<(), ProgramError> {
    require(flags & !VM_VALID_MASK == 0, DidError::InvalidFlags)?;
    if flags & (VM_FLAG_CAPABILITY_INVOCATION | VM_FLAG_PROTECTED) != 0 {
        require(method_type == VM_TYPE_ED25519, DidError::InvalidFlags)?;
    }
    if flags & VM_FLAG_PROTECTED != 0 {
        require(
            flags & VM_FLAG_CAPABILITY_INVOCATION != 0,
            DidError::InvalidFlags,
        )?;
    }
    if method_type == VM_TYPE_X25519 {
        require(
            flags & VM_RELATIONSHIP_MASK & !VM_FLAG_KEY_AGREEMENT == 0,
            DidError::InvalidFlags,
        )?;
    }
    if method_type == VM_TYPE_DILITHIUM5 {
        require(flags & VM_FLAG_KEY_AGREEMENT == 0, DidError::InvalidFlags)?;
    }
    Ok(())
}

/// A fragment is 1..=MAX_FRAGMENT_LEN characters of [A-Za-z0-9_-].
pub fn valid_fragment(fragment: &[u8]) -> bool {
    !fragment.is_empty()
        && fragment.len() <= MAX_FRAGMENT_LEN
        && fragment
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Printable ASCII without whitespace, of bounded length.
pub fn valid_uri_ascii(value: &[u8], max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && value.iter().all(|&b| (0x21..=0x7e).contains(&b))
}

/// An external controller is a DID of another method, `did:<method>:<id>`
/// as the DID syntax defines it. The method name is lowercase alphanumeric
/// and the method-specific id is non-empty, in printable ASCII of bounded
/// length. did:bio controllers use the native key form instead.
pub fn valid_external_controller(value: &[u8]) -> bool {
    if !valid_uri_ascii(value, MAX_CONTROLLER_LEN) {
        return false;
    }
    let Some(rest) = value.strip_prefix(b"did:") else {
        return false;
    };
    let Some(colon) = rest.iter().position(|&b| b == b':') else {
        return false;
    };
    let (method, id) = (&rest[..colon], &rest[colon + 1..]);
    !method.is_empty()
        && method != b"bio"
        && method
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !id.is_empty()
}

/// Bump `version`, saturating, and stamp `updated_at`.
#[inline]
pub fn touch(data: &mut [u8], now: i64) {
    let version = version(data);
    data[OFF_VERSION..OFF_VERSION + 8].copy_from_slice(&version.saturating_add(1).to_le_bytes());
    data[OFF_UPDATED_AT..OFF_UPDATED_AT + 8].copy_from_slice(&now.to_le_bytes());
}

/// Current `version` field.
#[inline]
pub fn version(data: &[u8]) -> u64 {
    let mut field = [0u8; 8];
    field.copy_from_slice(&data[OFF_VERSION..OFF_VERSION + 8]);
    u64::from_le_bytes(field)
}

#[cfg(test)]
mod owned_subject_tests {
    use super::*;

    /// Pinned across the resolver crate and the backend. The same inputs
    /// derive the same subject everywhere, and it is never a key.
    #[test]
    fn owned_subject_golden_vector() {
        let authority = [0x11u8; 32];
        assert_eq!(
            owned_subject(&authority, 42),
            [
                176, 5, 37, 51, 53, 114, 109, 56, 180, 140, 48, 89, 115, 119, 13, 138, 192, 54,
                110, 20, 205, 247, 212, 197, 39, 52, 9, 159, 203, 10, 250, 28
            ]
        );
        assert_ne!(owned_subject(&authority, 43), owned_subject(&authority, 42));
        assert!(!pinocchio::Address::new_from_array(owned_subject(&authority, 42)).is_on_curve());
    }
}
