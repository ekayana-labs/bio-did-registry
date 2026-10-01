//! A bounds-checked cursor over borrowed bytes, shared by the account layout
//! and the instruction arguments.
//!
//! The cursor consumes its input from the front. A read either returns the
//! bytes it consumed or fails with the error of the input's [`Source`], and a
//! failed read leaves the cursor where it was.

use core::marker::PhantomData;

use pinocchio::error::ProgramError;

/// The kind of input a [`Reader`] walks, which decides the error of a short
/// read.
pub trait Source {
    /// The error a read past the end raises.
    const ERROR: ProgramError;
}

/// Account data, where a short read is `InvalidAccountData`.
#[derive(Clone, Copy, Debug)]
pub enum Account {}

impl Source for Account {
    const ERROR: ProgramError = ProgramError::InvalidAccountData;
}

/// Instruction arguments, where a short read is `InvalidInstructionData`.
#[derive(Clone, Copy, Debug)]
pub enum Args {}

impl Source for Args {
    const ERROR: ProgramError = ProgramError::InvalidInstructionData;
}

/// A forward-only cursor over borrowed bytes. Every slice it returns borrows
/// the input, so nothing is copied.
#[derive(Debug)]
pub struct Reader<'a, S> {
    rest: &'a [u8],
    len: usize,
    source: PhantomData<fn() -> S>,
}

impl<S> Clone for Reader<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for Reader<'_, S> {}

impl<'a, S: Source> Reader<'a, S> {
    /// A cursor at the start of `data`.
    #[inline(always)]
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            rest: data,
            len: data.len(),
            source: PhantomData,
        }
    }

    /// A cursor `offset` bytes into `data`.
    #[inline(always)]
    pub fn at(data: &'a [u8], offset: usize) -> Result<Self, ProgramError> {
        Ok(Self {
            rest: data.get(offset..).ok_or(S::ERROR)?,
            len: data.len(),
            source: PhantomData,
        })
    }

    /// How far the cursor is from the start of the input.
    #[inline(always)]
    pub const fn offset(&self) -> usize {
        self.len - self.rest.len()
    }

    /// The bytes not consumed yet.
    #[inline(always)]
    pub const fn remaining(&self) -> &'a [u8] {
        self.rest
    }

    /// The next `n` bytes.
    #[inline(always)]
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let (head, rest) = self.rest.split_at_checked(n).ok_or(S::ERROR)?;
        self.rest = rest;
        Ok(head)
    }

    /// The next `N` bytes as an array.
    #[inline(always)]
    pub fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], ProgramError> {
        let (head, rest) = self.rest.split_first_chunk::<N>().ok_or(S::ERROR)?;
        self.rest = rest;
        Ok(head)
    }

    #[inline(always)]
    pub fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.array::<1>()?[0])
    }

    #[inline(always)]
    pub fn u16(&mut self) -> Result<u16, ProgramError> {
        Ok(u16::from_le_bytes(*self.array()?))
    }

    #[inline(always)]
    pub fn u32(&mut self) -> Result<u32, ProgramError> {
        Ok(u32::from_le_bytes(*self.array()?))
    }

    #[inline(always)]
    pub fn u64(&mut self) -> Result<u64, ProgramError> {
        Ok(u64::from_le_bytes(*self.array()?))
    }

    /// A borsh `Vec<u8>` or the payload of a `String`, which is a u32 length
    /// prefix and then that many bytes.
    #[inline(always)]
    pub fn len_prefixed(&mut self) -> Result<&'a [u8], ProgramError> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }

    /// Checks that the input ends here.
    #[inline(always)]
    pub fn finish(self) -> Result<(), ProgramError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(S::ERROR)
        }
    }
}

impl<'a> Reader<'a, Args> {
    /// A borsh `String`, whose payload must be valid UTF-8. Borsh enforces
    /// this, so malformed arguments fail here the same way.
    #[inline(always)]
    pub fn str(&mut self) -> Result<&'a [u8], ProgramError> {
        let bytes = self.len_prefixed()?;
        core::str::from_utf8(bytes).map_err(|_| ProgramError::InvalidInstructionData)?;
        Ok(bytes)
    }
}
