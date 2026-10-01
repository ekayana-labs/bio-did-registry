//! The client builders against the program. Every instruction a builder
//! makes is sent through LiteSVM, so the builders and the program agree on
//! accounts and encoding, and failures decode to the program's errors.
//!
//! Build the program first with
//! `cargo build-sbf --manifest-path program/Cargo.toml`.

use std::path::PathBuf;

use bio_did_registry::{client, error::DidError, state};
use litesvm::LiteSVM;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

fn setup() -> LiteSVM {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/bio_did_registry.so");
    let so =
        std::fs::read(&path).expect("run cargo build-sbf --manifest-path program/Cargo.toml first");
    let mut svm = LiteSVM::new();
    svm.add_program(
        Pubkey::new_from_array(*bio_did_registry::ID.as_array()),
        &so,
    )
    .unwrap();
    svm
}

fn sdk(ix: client::Instruction) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(ix.program_id),
        accounts: ix
            .accounts
            .into_iter()
            .map(|meta| AccountMeta {
                pubkey: Pubkey::new_from_array(meta.address),
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            })
            .collect(),
        data: ix.data,
    }
}

/// Sends one builder instruction, decoding a custom error to `DidError`.
fn send(svm: &mut LiteSVM, ix: client::Instruction, signers: &[&Keypair]) -> Result<(), String> {
    svm.expire_blockhash();
    let msg = Message::new_with_blockhash(
        &[sdk(ix)],
        Some(&signers[0].pubkey()),
        &svm.latest_blockhash(),
    );
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), signers).unwrap();
    svm.send_transaction(tx).map(|_| ()).map_err(|e| {
        let text = format!("{:?}", e.err);
        match text
            .split("Custom(")
            .nth(1)
            .and_then(|rest| rest.split(')').next())
            .and_then(|code| code.parse::<u32>().ok())
            .and_then(DidError::from_code)
        {
            Some(err) => format!("{err:?}: {err}"),
            None => text,
        }
    })
}

fn decode(svm: &LiteSVM, subject: &[u8; 32]) -> Vec<u8> {
    let address = Pubkey::new_from_array(client::did_account(subject));
    svm.get_account(&address).unwrap().data
}

#[test]
fn builders_drive_a_whole_lifecycle() {
    let mut svm = setup();
    let wallet = Keypair::new();
    let lab = Keypair::new();
    svm.airdrop(&wallet.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&lab.pubkey(), 10_000_000_000).unwrap();
    let w = wallet.pubkey().to_bytes();
    let l = lab.pubkey().to_bytes();

    send(&mut svm, client::initialize(&l, &l), &[&lab]).unwrap();
    send(&mut svm, client::initialize_owned(&w, &w, 9), &[&wallet]).unwrap();
    let dataset = state::owned_subject(&w, 9);

    send(
        &mut svm,
        client::add_service(&w, &w, &dataset, "metadata", "BioMetadata", "ipfs://a"),
        &[&wallet],
    )
    .unwrap();
    send(
        &mut svm,
        client::update_service(&w, &w, &dataset, "metadata", "BioMetadata", "ipfs://b"),
        &[&wallet],
    )
    .unwrap();
    send(
        &mut svm,
        client::set_controllers(&w, &w, &dataset, &[l], &["did:web:lab.example.org"]),
        &[&wallet],
    )
    .unwrap();

    // The lab acts through its controller account.
    let key = Keypair::new().pubkey().to_bytes();
    send(
        &mut svm,
        client::add_verification_method(
            &l,
            &l,
            &dataset,
            "lab",
            state::VM_TYPE_ED25519,
            state::VM_FLAG_AUTHENTICATION,
            &key,
        )
        .via_controller(&l),
        &[&lab],
    )
    .unwrap();
    send(
        &mut svm,
        client::set_verification_method_flags(&l, &dataset, "lab", state::VM_FLAG_ASSERTION)
            .via_controller(&l),
        &[&lab],
    )
    .unwrap();

    // A post-quantum key travels through a key buffer, one transaction per
    // instruction.
    let pq: Vec<u8> = (0..2592u32).map(|i| (i % 251) as u8).collect();
    let upload = client::upload_key(
        &w,
        &w,
        &dataset,
        "pq",
        state::VM_TYPE_DILITHIUM5,
        state::VM_FLAG_ASSERTION,
        &pq,
    );
    assert_eq!(upload.len(), 5);
    for ix in upload {
        send(&mut svm, ix, &[&wallet]).unwrap();
    }
    let data = decode(&svm, &dataset);
    assert!(data.windows(pq.len()).any(|window| window == pq));

    // An abandoned upload is reclaimed.
    send(
        &mut svm,
        client::create_key_buffer(
            &w,
            &w,
            &dataset,
            "pq2",
            state::VM_TYPE_DILITHIUM5,
            state::VM_FLAG_ASSERTION,
            2592,
        ),
        &[&wallet],
    )
    .unwrap();
    send(
        &mut svm,
        client::close_key_buffer(&w, &w, &dataset),
        &[&wallet],
    )
    .unwrap();
    let buffer = Pubkey::new_from_array(client::key_buffer(&dataset, &w));
    assert!(svm.get_account(&buffer).is_none_or(|a| a.lamports == 0));

    send(
        &mut svm,
        client::remove_verification_method(&w, &w, &dataset, "pq"),
        &[&wallet],
    )
    .unwrap();
    send(
        &mut svm,
        client::remove_service(&w, &w, &dataset, "metadata"),
        &[&wallet],
    )
    .unwrap();

    // Failures decode to the program's own errors.
    let err = send(
        &mut svm,
        client::remove_service(&w, &w, &dataset, "metadata"),
        &[&wallet],
    )
    .unwrap_err();
    assert_eq!(
        err,
        format!("ServiceNotFound: {}", DidError::ServiceNotFound)
    );
    let err = send(&mut svm, client::deactivate(&l, &l, &dataset), &[&lab]).unwrap_err();
    assert!(err.starts_with("Unauthorized"), "{err}");

    send(&mut svm, client::deactivate(&w, &w, &dataset), &[&wallet]).unwrap();
    assert_eq!(decode(&svm, &dataset).len(), state::TOMBSTONE_SPACE);
}

#[test]
fn builders_encode_the_documented_layout() {
    let payer = [1u8; 32];
    let subject = [2u8; 32];
    let ix = client::add_service(&payer, &payer, &subject, "m", "T", "e");
    assert_eq!(ix.program_id, *bio_did_registry::ID.as_array());
    let mut data = bio_did_registry::ix::ADD_SERVICE.to_vec();
    for part in ["m", "T", "e"] {
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(part.as_bytes());
    }
    assert_eq!(ix.data, data);
    assert_eq!(
        ix.accounts,
        [
            client::AccountMeta::writable(payer, true),
            client::AccountMeta::readonly(payer, true),
            client::AccountMeta::writable(client::did_account(&subject), false),
            client::AccountMeta::readonly(client::SYSTEM_PROGRAM, false),
        ]
    );
    let via = ix.clone().via_controller(&[3u8; 32]);
    assert_eq!(via.accounts.len(), 5);
    assert_eq!(
        via.accounts[4],
        client::AccountMeta::readonly(client::did_account(&[3u8; 32]), false)
    );
    assert_eq!(
        client::initialize_owned(&payer, &payer, 42).accounts[2].address,
        client::did_account(&state::owned_subject(&payer, 42))
    );
}
