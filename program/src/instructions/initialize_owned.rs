//! Materialize a DID whose subject is derived by the program instead of
//! being an Ed25519 key: `subject = find_program_address(["bio-did-owned",
//! authority, nonce_le])`. The address is off the curve, so no keypair can
//! ever stand behind it and the DID has no generative document; the signing
//! authority's key becomes its protected `#default` verification method.
//!
//! One signature creates a DID the signer controls, which is how a wallet
//! names a dataset, paper or claim it owns and pays for. Because the
//! authority must sign, nobody can register an owned DID in someone else's
//! name, and distinct authorities can never collide on a nonce.
//!
//! ABI: [payer, authority, did_account, system_program]; args: nonce u64 LE.
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::{
    instructions::{initialize, shared::*},
    state::owned_subject_seeds,
};

pub fn process(accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let [payer, authority, did_account, system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_authority_signer(authority)?;
    let nonce: [u8; 8] = args
        .get(0..8)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .unwrap();
    let authority_key: &[u8; 32] = authority.address().as_array();
    let (subject, _) =
        Address::find_program_address(&owned_subject_seeds(authority_key, &nonce), &crate::ID);
    initialize::materialize(
        payer,
        did_account,
        system_program,
        subject.as_array(),
        authority_key,
    )
}
