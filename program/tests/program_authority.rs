//! Program authorities. A program address has no private key, so it signs
//! only through a CPI from the program that owns it. The `cpi-caller`
//! fixture forwards registry instructions and signs as its address, the way
//! a multisig or a DAO vault would.
//!
//! Build both programs first with
//! `cargo build-sbf --manifest-path program/Cargo.toml` and
//! `cargo build-sbf --manifest-path program/tests/fixtures/cpi-caller/Cargo.toml`.

use std::path::PathBuf;

use bio_did_registry::{client, state};
use litesvm::LiteSVM;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

fn registry() -> Pubkey {
    Pubkey::new_from_array(*bio_did_registry::ID.as_array())
}

fn caller() -> Pubkey {
    Pubkey::new_from_array([0xca; 32])
}

/// The seed of the caller's signing address, as `cpi-caller` defines it.
const AUTHORITY_SEED: &[u8] = b"authority";

fn so(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/deploy")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("{} not found, build it first", path.display()))
}

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    svm.add_program(registry(), &so("bio_did_registry.so"))
        .unwrap();
    svm.add_program(caller(), &so("cpi_caller.so")).unwrap();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    (svm, payer)
}

/// The caller's address and bump.
fn vault() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[AUTHORITY_SEED], &caller())
}

fn sdk(ix: client::Instruction) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(ix.program_id),
        accounts: ix
            .accounts
            .into_iter()
            .map(|m| AccountMeta {
                pubkey: Pubkey::new_from_array(m.address),
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
            .collect(),
        data: ix.data,
    }
}

/// Wraps a registry instruction for the caller. The vault appears as a plain
/// account, and the caller signs for it.
fn through_caller(ix: client::Instruction) -> Instruction {
    let (vault, bump) = vault();
    let inner = sdk(ix);
    let mut accounts = vec![AccountMeta::new_readonly(registry(), false)];
    accounts.extend(inner.accounts.into_iter().map(|mut meta| {
        if meta.pubkey == vault {
            meta.is_signer = false;
        }
        meta
    }));
    let mut data = vec![bump];
    data.extend(inner.data);
    Instruction {
        program_id: caller(),
        accounts,
        data,
    }
}

fn send(svm: &mut LiteSVM, ix: Instruction, signer: &Keypair) -> Result<(), String> {
    svm.expire_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&signer.pubkey()), &svm.latest_blockhash());
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[signer]).unwrap();
    svm.send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{:?}", e.err))
}

fn methods(svm: &LiteSVM, subject: &[u8; 32]) -> Vec<(String, Vec<u8>)> {
    let address = Pubkey::new_from_array(client::did_account(subject));
    let data = svm.get_account(&address).unwrap().data;
    let view = state::DidView::parse(&data).unwrap();
    view.vms()
        .map(|vm| {
            (
                String::from_utf8(vm.fragment.to_vec()).unwrap(),
                vm.key.to_vec(),
            )
        })
        .collect()
}

#[test]
fn a_program_creates_and_controls_an_owned_did() {
    let (mut svm, payer) = setup();
    let p = payer.pubkey().to_bytes();
    let (vault, _) = vault();
    let v = vault.to_bytes();
    assert!(!vault.is_on_curve());

    // The vault signs `initialize_owned` through the caller, so its address
    // becomes the protected `#default` key although it is off the curve.
    send(
        &mut svm,
        through_caller(client::initialize_owned(&p, &v, 1)),
        &payer,
    )
    .unwrap();
    let dataset = state::owned_subject(&v, 1);
    assert_eq!(
        methods(&svm, &dataset),
        [("default".to_string(), v.to_vec())]
    );

    // It updates the DID the same way, and nobody else can.
    send(
        &mut svm,
        through_caller(client::add_service(
            &p,
            &v,
            &dataset,
            "metadata",
            "BioMetadata",
            "ipfs://x",
        )),
        &payer,
    )
    .unwrap();
    let err = send(
        &mut svm,
        sdk(client::add_service(
            &p,
            &p,
            &dataset,
            "other",
            "BioMetadata",
            "ipfs://y",
        )),
        &payer,
    )
    .unwrap_err();
    assert!(err.contains("Custom(6000)"), "{err}");

    // An off-curve key enters only as the signer itself. The vault may add
    // its own address again, and no other program address.
    send(
        &mut svm,
        through_caller(client::add_verification_method(
            &p,
            &v,
            &dataset,
            "vault",
            state::VM_TYPE_ED25519,
            state::VM_FLAG_CAPABILITY_INVOCATION,
            &v,
        )),
        &payer,
    )
    .unwrap();
    let other = state::owned_subject(&p, 5);
    let err = send(
        &mut svm,
        through_caller(client::add_verification_method(
            &p,
            &v,
            &dataset,
            "ghost",
            state::VM_TYPE_ED25519,
            state::VM_FLAG_CAPABILITY_INVOCATION,
            &other,
        )),
        &payer,
    )
    .unwrap_err();
    assert!(err.contains("Custom(6018)"), "{err}");

    // A wallet that controls a DID cannot name the vault as an authority,
    // since the vault does not sign that transaction.
    send(&mut svm, sdk(client::initialize(&p, &p)), &payer).unwrap();
    let err = send(
        &mut svm,
        sdk(client::add_verification_method(
            &p,
            &p,
            &p,
            "vault",
            state::VM_TYPE_ED25519,
            state::VM_FLAG_CAPABILITY_INVOCATION,
            &v,
        )),
        &payer,
    )
    .unwrap_err();
    assert!(err.contains("Custom(6018)"), "{err}");
}

#[test]
fn a_program_controls_dids_through_its_own() {
    let (mut svm, payer) = setup();
    let p = payer.pubkey().to_bytes();
    let (vault, _) = vault();
    let v = vault.to_bytes();

    // The vault owns a DID, and a wallet lists that DID as the native
    // controller of a dataset it creates.
    send(
        &mut svm,
        through_caller(client::initialize_owned(&p, &v, 1)),
        &payer,
    )
    .unwrap();
    let lab = state::owned_subject(&v, 1);
    send(&mut svm, sdk(client::initialize_owned(&p, &p, 2)), &payer).unwrap();
    let dataset = state::owned_subject(&p, 2);
    send(
        &mut svm,
        sdk(client::set_controllers(&p, &p, &dataset, &[lab], &[])),
        &payer,
    )
    .unwrap();

    // The vault acts on the dataset through the lab's registry account.
    send(
        &mut svm,
        through_caller(
            client::add_service(&p, &v, &dataset, "metadata", "BioMetadata", "ipfs://x")
                .via_controller(&lab),
        ),
        &payer,
    )
    .unwrap();
    let data = svm
        .get_account(&Pubkey::new_from_array(client::did_account(&dataset)))
        .unwrap()
        .data;
    assert_eq!(state::DidView::parse(&data).unwrap().services().count(), 1);
}
