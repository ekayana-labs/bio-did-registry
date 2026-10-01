//! Instruction builders for clients, available off chain.
//!
//! Each builder returns an [`Instruction`] holding the program ID, the
//! account metas in the order the program reads them and the borsh encoded
//! arguments. Addresses are plain 32 byte arrays, so an instruction converts
//! into the types of any Solana SDK generation. The builders only encode.
//! The checks the program applies live in [`crate::state`], for clients that
//! want to refuse a request before sending it.
//!
//! ```
//! use bio_did_registry::client;
//!
//! let wallet = [7u8; 32];
//! let ix = client::add_service(&wallet, &wallet, &wallet, "metadata", "BioMetadata", "ipfs://x");
//! assert_eq!(ix.data[..8], bio_did_registry::ix::ADD_SERVICE);
//! assert_eq!(ix.accounts[2].address, client::did_account(&wallet));
//! ```

use std::vec::Vec;

use crate::state::{owned_subject, DID_SEED, KEY_BUFFER_SEED};

/// The system program, `11111111111111111111111111111111`.
pub const SYSTEM_PROGRAM: [u8; 32] = [0; 32];

/// The chunk size [`upload_key`] writes, which keeps every `write_key_buffer`
/// transaction under the 1232 byte limit even with a separate fee payer.
pub const KEY_CHUNK_LEN: usize = 900;

/// An account an instruction reads, with its signer and writable roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountMeta {
    pub address: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    /// A writable account.
    pub const fn writable(address: [u8; 32], is_signer: bool) -> Self {
        Self {
            address,
            is_signer,
            is_writable: true,
        }
    }

    /// A read-only account.
    pub const fn readonly(address: [u8; 32], is_signer: bool) -> Self {
        Self {
            address,
            is_signer,
            is_writable: false,
        }
    }
}

/// One registry instruction, ready to convert into an SDK instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

impl Instruction {
    fn new(discriminator: [u8; 8], accounts: Vec<AccountMeta>) -> Self {
        Self {
            program_id: *crate::ID.as_array(),
            accounts,
            data: discriminator.to_vec(),
        }
    }

    fn str(self, value: &str) -> Self {
        self.bytes(value.as_bytes())
    }

    fn bytes(mut self, value: &[u8]) -> Self {
        self.data
            .extend_from_slice(&(value.len() as u32).to_le_bytes());
        self.data.extend_from_slice(value);
        self
    }

    fn raw(mut self, value: &[u8]) -> Self {
        self.data.extend_from_slice(value);
        self
    }

    /// Appends the registry account of `controller`, a native controller of
    /// the DID. The program reads it when the signer is not one of the DID's
    /// own authorities but is an authority of the controller.
    pub fn via_controller(mut self, controller: &[u8; 32]) -> Self {
        self.accounts
            .push(AccountMeta::readonly(did_account(controller), false));
        self
    }
}

/// The registry account of `subject`, `["bio-did", subject]`.
pub fn did_account(subject: &[u8; 32]) -> [u8; 32] {
    let (address, _) = pinocchio::Address::find_program_address(&[DID_SEED, subject], &crate::ID);
    *address.as_array()
}

/// The key buffer `authority` uploads into for the DID of `subject`,
/// `["bio-did-key", did_account, authority]`.
pub fn key_buffer(subject: &[u8; 32], authority: &[u8; 32]) -> [u8; 32] {
    let (address, _) = pinocchio::Address::find_program_address(
        &[KEY_BUFFER_SEED, &did_account(subject), authority],
        &crate::ID,
    );
    *address.as_array()
}

fn update_accounts(payer: &[u8; 32], authority: &[u8; 32], subject: &[u8; 32]) -> Vec<AccountMeta> {
    std::vec![
        AccountMeta::writable(*payer, true),
        AccountMeta::readonly(*authority, true),
        AccountMeta::writable(did_account(subject), false),
        AccountMeta::readonly(SYSTEM_PROGRAM, false),
    ]
}

fn buffer_accounts(payer: &[u8; 32], authority: &[u8; 32], subject: &[u8; 32]) -> Vec<AccountMeta> {
    std::vec![
        AccountMeta::writable(*payer, true),
        AccountMeta::readonly(*authority, true),
        AccountMeta::writable(did_account(subject), false),
        AccountMeta::writable(key_buffer(subject, authority), false),
        AccountMeta::readonly(SYSTEM_PROGRAM, false),
    ]
}

/// Creates the registry account of a key subject. Any payer may sponsor it.
pub fn initialize(payer: &[u8; 32], subject: &[u8; 32]) -> Instruction {
    Instruction::new(
        crate::ix::INITIALIZE,
        std::vec![
            AccountMeta::writable(*payer, true),
            AccountMeta::writable(did_account(subject), false),
            AccountMeta::readonly(SYSTEM_PROGRAM, false),
        ],
    )
    .raw(subject)
}

/// Creates the owned DID of `authority` and `nonce`, whose subject is
/// [`owned_subject`]. The authority signs and becomes its `#default` method.
pub fn initialize_owned(payer: &[u8; 32], authority: &[u8; 32], nonce: u64) -> Instruction {
    let subject = owned_subject(authority, nonce);
    Instruction::new(
        crate::ix::INITIALIZE_OWNED,
        update_accounts(payer, authority, &subject),
    )
    .raw(&nonce.to_le_bytes())
}

/// Adds a verification method whose key fits in one transaction.
pub fn add_verification_method(
    payer: &[u8; 32],
    authority: &[u8; 32],
    subject: &[u8; 32],
    fragment: &str,
    method_type: u8,
    flags: u16,
    key: &[u8],
) -> Instruction {
    Instruction::new(
        crate::ix::ADD_VERIFICATION_METHOD,
        update_accounts(payer, authority, subject),
    )
    .str(fragment)
    .raw(&[method_type])
    .raw(&flags.to_le_bytes())
    .bytes(key)
}

/// Removes the verification method named `fragment`.
pub fn remove_verification_method(
    payer: &[u8; 32],
    authority: &[u8; 32],
    subject: &[u8; 32],
    fragment: &str,
) -> Instruction {
    Instruction::new(
        crate::ix::REMOVE_VERIFICATION_METHOD,
        update_accounts(payer, authority, subject),
    )
    .str(fragment)
}

/// Replaces the flags of the verification method named `fragment`. This is
/// the one update without a payer, since it never resizes the account.
pub fn set_verification_method_flags(
    authority: &[u8; 32],
    subject: &[u8; 32],
    fragment: &str,
    flags: u16,
) -> Instruction {
    Instruction::new(
        crate::ix::SET_VERIFICATION_METHOD_FLAGS,
        std::vec![
            AccountMeta::readonly(*authority, true),
            AccountMeta::writable(did_account(subject), false),
        ],
    )
    .str(fragment)
    .raw(&flags.to_le_bytes())
}

/// Adds a service.
pub fn add_service(
    payer: &[u8; 32],
    authority: &[u8; 32],
    subject: &[u8; 32],
    fragment: &str,
    service_type: &str,
    endpoint: &str,
) -> Instruction {
    Instruction::new(
        crate::ix::ADD_SERVICE,
        update_accounts(payer, authority, subject),
    )
    .str(fragment)
    .str(service_type)
    .str(endpoint)
}

/// Replaces the type and endpoint of the service named `fragment`.
pub fn update_service(
    payer: &[u8; 32],
    authority: &[u8; 32],
    subject: &[u8; 32],
    fragment: &str,
    service_type: &str,
    endpoint: &str,
) -> Instruction {
    Instruction::new(
        crate::ix::UPDATE_SERVICE,
        update_accounts(payer, authority, subject),
    )
    .str(fragment)
    .str(service_type)
    .str(endpoint)
}

/// Removes the service named `fragment`.
pub fn remove_service(
    payer: &[u8; 32],
    authority: &[u8; 32],
    subject: &[u8; 32],
    fragment: &str,
) -> Instruction {
    Instruction::new(
        crate::ix::REMOVE_SERVICE,
        update_accounts(payer, authority, subject),
    )
    .str(fragment)
}

/// Replaces both controller sets, native subjects and external DIDs.
pub fn set_controllers(
    payer: &[u8; 32],
    authority: &[u8; 32],
    subject: &[u8; 32],
    native: &[[u8; 32]],
    external: &[&str],
) -> Instruction {
    let mut ix = Instruction::new(
        crate::ix::SET_CONTROLLERS,
        update_accounts(payer, authority, subject),
    )
    .raw(&(native.len() as u32).to_le_bytes());
    for key in native {
        ix = ix.raw(key);
    }
    ix = ix.raw(&(external.len() as u32).to_le_bytes());
    for did in external {
        ix = ix.str(did);
    }
    ix
}

/// Deactivates the DID for good.
pub fn deactivate(payer: &[u8; 32], authority: &[u8; 32], subject: &[u8; 32]) -> Instruction {
    Instruction::new(
        crate::ix::DEACTIVATE,
        update_accounts(payer, authority, subject),
    )
}

/// Opens the key buffer of `authority` for a method whose key is `key_len`
/// bytes long.
pub fn create_key_buffer(
    payer: &[u8; 32],
    authority: &[u8; 32],
    subject: &[u8; 32],
    fragment: &str,
    method_type: u8,
    flags: u16,
    key_len: u32,
) -> Instruction {
    Instruction::new(
        crate::ix::CREATE_KEY_BUFFER,
        buffer_accounts(payer, authority, subject),
    )
    .str(fragment)
    .raw(&[method_type])
    .raw(&flags.to_le_bytes())
    .raw(&key_len.to_le_bytes())
}

/// Writes `chunk` at `offset`, which must be where the previous chunk ended.
pub fn write_key_buffer(
    authority: &[u8; 32],
    subject: &[u8; 32],
    offset: u32,
    chunk: &[u8],
) -> Instruction {
    Instruction::new(
        crate::ix::WRITE_KEY_BUFFER,
        std::vec![
            AccountMeta::readonly(*authority, true),
            AccountMeta::writable(key_buffer(subject, authority), false),
        ],
    )
    .raw(&offset.to_le_bytes())
    .bytes(chunk)
}

/// Appends the method staged in a complete key buffer and closes the buffer.
pub fn add_verification_method_from_buffer(
    payer: &[u8; 32],
    authority: &[u8; 32],
    subject: &[u8; 32],
) -> Instruction {
    Instruction::new(
        crate::ix::ADD_VERIFICATION_METHOD_FROM_BUFFER,
        buffer_accounts(payer, authority, subject),
    )
}

/// Discards the key buffer of `authority` and refunds its rent.
pub fn close_key_buffer(payer: &[u8; 32], authority: &[u8; 32], subject: &[u8; 32]) -> Instruction {
    Instruction::new(
        crate::ix::CLOSE_KEY_BUFFER,
        std::vec![
            AccountMeta::writable(*payer, true),
            AccountMeta::readonly(*authority, true),
            AccountMeta::writable(key_buffer(subject, authority), false),
        ],
    )
}

/// The instructions that register a key too large for one transaction, in
/// order. They open a key buffer, write the key in [`KEY_CHUNK_LEN`] chunks
/// and append the method. Each goes in a transaction of its own, so an
/// interrupted upload can resume from the buffer's `written` count.
pub fn upload_key(
    payer: &[u8; 32],
    authority: &[u8; 32],
    subject: &[u8; 32],
    fragment: &str,
    method_type: u8,
    flags: u16,
    key: &[u8],
) -> Vec<Instruction> {
    let mut ixs = std::vec![create_key_buffer(
        payer,
        authority,
        subject,
        fragment,
        method_type,
        flags,
        key.len() as u32,
    )];
    for (i, chunk) in key.chunks(KEY_CHUNK_LEN).enumerate() {
        ixs.push(write_key_buffer(
            authority,
            subject,
            (i * KEY_CHUNK_LEN) as u32,
            chunk,
        ));
    }
    ixs.push(add_verification_method_from_buffer(
        payer, authority, subject,
    ));
    ixs
}
