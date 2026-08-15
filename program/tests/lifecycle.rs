//! LiteSVM integration tests for the did:bio registry program.
//!
//! Every instruction is encoded by hand from the wire format and every
//! account is decoded by an independent parser defined in this file - the
//! program crate's own types are deliberately not used, so these tests pin
//! the on-chain format itself, not the implementation's view of it.
//!
//! Build the program first: `cargo build-sbf --manifest-path program/Cargo.toml`

use std::path::PathBuf;
use std::str::FromStr;

use litesvm::LiteSVM;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

const AIRDROP: u64 = 10_000_000_000;
const PROGRAM_ID: &str = "H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// sha256("account:DidAccount")[..8].
const ACCOUNT_DISCRIMINATOR: [u8; 8] = [77, 88, 239, 141, 251, 29, 237, 243];

// Instruction discriminators (sha256("global:<name>")[..8]).
const IX_INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
const IX_ADD_VM: [u8; 8] = [213, 200, 190, 61, 28, 104, 245, 25];
const IX_REMOVE_VM: [u8; 8] = [33, 238, 66, 183, 62, 210, 133, 150];
const IX_SET_VM_FLAGS: [u8; 8] = [16, 188, 26, 223, 241, 131, 192, 223];
const IX_ADD_SERVICE: [u8; 8] = [133, 207, 106, 32, 91, 111, 153, 30];
const IX_REMOVE_SERVICE: [u8; 8] = [19, 102, 8, 231, 40, 141, 9, 110];
const IX_SET_CONTROLLERS: [u8; 8] = [65, 40, 24, 8, 30, 81, 20, 179];
const IX_DEACTIVATE: [u8; 8] = [44, 112, 33, 172, 113, 28, 142, 13];

const VM_FLAG_AUTHENTICATION: u16 = 1 << 0;
const VM_FLAG_ASSERTION: u16 = 1 << 1;
const VM_FLAG_KEY_AGREEMENT: u16 = 1 << 2;
const VM_FLAG_CAPABILITY_INVOCATION: u16 = 1 << 3;
const VM_FLAG_PROTECTED: u16 = 1 << 8;
const VM_FLAGS_DEFAULT: u16 = 0b1_1111 | VM_FLAG_PROTECTED;

const VM_TYPE_ED25519: u8 = 0;
const VM_TYPE_X25519: u8 = 1;
const VM_TYPE_DILITHIUM5: u8 = 3;

const INITIAL_SPACE: usize = 124;
const TOMBSTONE_SPACE: usize = 74;

fn program_id() -> Pubkey {
    Pubkey::from_str(PROGRAM_ID).unwrap()
}

fn system_program() -> Pubkey {
    Pubkey::from_str(SYSTEM_PROGRAM).unwrap()
}

fn program_so() -> Vec<u8> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/did_bio_registry.so");
    std::fs::read(&path).unwrap_or_else(|_| {
        panic!(
            "{} not found - run `cargo build-sbf --manifest-path program/Cargo.toml` first",
            path.display(),
        )
    })
}

fn setup() -> LiteSVM {
    let mut svm = LiteSVM::new();
    svm.add_program(program_id(), &program_so()).unwrap();
    svm
}

fn did_pda(subject: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"bio-did", subject.as_ref()], &program_id()).0
}

// ---------------------------------------------------------------------------
// Independent account decoder (wire format per the did:bio method spec)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct Vm {
    fragment: String,
    method_type: u8,
    flags: u16,
    key_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
struct Svc {
    fragment: String,
    service_type: String,
    endpoint: String,
}

#[derive(Debug, Clone, PartialEq)]
struct Did {
    version: u64,
    bump: u8,
    subject: [u8; 32],
    deactivated: bool,
    updated_at: i64,
    native_controllers: Vec<[u8; 32]>,
    other_controllers: Vec<String>,
    verification_methods: Vec<Vm>,
    services: Vec<Svc>,
}

struct Cursor<'a> {
    data: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn bytes(&mut self, n: usize) -> &'a [u8] {
        let out = &self.data[self.off..self.off + n];
        self.off += n;
        out
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.bytes(4).try_into().unwrap())
    }
    fn string(&mut self) -> String {
        let len = self.u32() as usize;
        String::from_utf8(self.bytes(len).to_vec()).unwrap()
    }
}

/// Parse a DidAccount, asserting the discriminator and that the buffer is
/// consumed exactly (no trailing bytes: the account is always exact-size).
fn parse_did(data: &[u8]) -> Did {
    assert_eq!(data[0..8], ACCOUNT_DISCRIMINATOR, "account discriminator");
    let mut c = Cursor { data, off: 8 };
    let version = u64::from_le_bytes(c.bytes(8).try_into().unwrap());
    let bump = c.bytes(1)[0];
    let subject: [u8; 32] = c.bytes(32).try_into().unwrap();
    let deactivated = match c.bytes(1)[0] {
        0 => false,
        1 => true,
        b => panic!("invalid bool byte {b}"),
    };
    let updated_at = i64::from_le_bytes(c.bytes(8).try_into().unwrap());
    let native_controllers = (0..c.u32())
        .map(|_| c.bytes(32).try_into().unwrap())
        .collect();
    let other_controllers = (0..c.u32()).map(|_| c.string()).collect();
    let verification_methods = (0..c.u32())
        .map(|_| {
            let fragment = c.string();
            let method_type = c.bytes(1)[0];
            let flags = u16::from_le_bytes(c.bytes(2).try_into().unwrap());
            let key_len = c.u32() as usize;
            let key_data = c.bytes(key_len).to_vec();
            Vm {
                fragment,
                method_type,
                flags,
                key_data,
            }
        })
        .collect();
    let services = (0..c.u32())
        .map(|_| Svc {
            fragment: c.string(),
            service_type: c.string(),
            endpoint: c.string(),
        })
        .collect();
    assert_eq!(c.off, data.len(), "account must be exact-size");
    Did {
        version,
        bump,
        subject,
        deactivated,
        updated_at,
        native_controllers,
        other_controllers,
        verification_methods,
        services,
    }
}

fn decode(svm: &LiteSVM, pda: &Pubkey) -> Did {
    let account = svm.get_account(pda).unwrap();
    assert_eq!(account.owner, program_id(), "account owner");
    parse_did(&account.data)
}

fn account_len(svm: &LiteSVM, pda: &Pubkey) -> usize {
    svm.get_account(pda).unwrap().data.len()
}

// ---------------------------------------------------------------------------
// Wire-format instruction encoding
// ---------------------------------------------------------------------------

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

fn mutate_metas(payer: &Pubkey, authority: &Pubkey, subject: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new(did_pda(subject), false),
        AccountMeta::new_readonly(system_program(), false),
    ]
}

fn initialize_ix(payer: &Pubkey, subject: &Pubkey) -> Instruction {
    let mut data = IX_INITIALIZE.to_vec();
    data.extend_from_slice(subject.as_ref());
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(did_pda(subject), false),
            AccountMeta::new_readonly(system_program(), false),
        ],
        data,
    }
}

#[allow(clippy::too_many_arguments)]
fn add_vm_ix(
    payer: &Pubkey,
    authority: &Pubkey,
    subject: &Pubkey,
    fragment: &str,
    method_type: u8,
    flags: u16,
    key_data: &[u8],
) -> Instruction {
    let mut data = IX_ADD_VM.to_vec();
    put_str(&mut data, fragment);
    data.push(method_type);
    data.extend_from_slice(&flags.to_le_bytes());
    put_bytes(&mut data, key_data);
    Instruction {
        program_id: program_id(),
        accounts: mutate_metas(payer, authority, subject),
        data,
    }
}

fn remove_vm_ix(
    payer: &Pubkey,
    authority: &Pubkey,
    subject: &Pubkey,
    fragment: &str,
) -> Instruction {
    let mut data = IX_REMOVE_VM.to_vec();
    put_str(&mut data, fragment);
    Instruction {
        program_id: program_id(),
        accounts: mutate_metas(payer, authority, subject),
        data,
    }
}

fn set_flags_ix(authority: &Pubkey, subject: &Pubkey, fragment: &str, flags: u16) -> Instruction {
    let mut data = IX_SET_VM_FLAGS.to_vec();
    put_str(&mut data, fragment);
    data.extend_from_slice(&flags.to_le_bytes());
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(did_pda(subject), false),
        ],
        data,
    }
}

fn add_service_ix(
    payer: &Pubkey,
    authority: &Pubkey,
    subject: &Pubkey,
    fragment: &str,
    service_type: &str,
    endpoint: &str,
) -> Instruction {
    let mut data = IX_ADD_SERVICE.to_vec();
    put_str(&mut data, fragment);
    put_str(&mut data, service_type);
    put_str(&mut data, endpoint);
    Instruction {
        program_id: program_id(),
        accounts: mutate_metas(payer, authority, subject),
        data,
    }
}

fn remove_service_ix(
    payer: &Pubkey,
    authority: &Pubkey,
    subject: &Pubkey,
    fragment: &str,
) -> Instruction {
    let mut data = IX_REMOVE_SERVICE.to_vec();
    put_str(&mut data, fragment);
    Instruction {
        program_id: program_id(),
        accounts: mutate_metas(payer, authority, subject),
        data,
    }
}

fn set_controllers_ix(
    payer: &Pubkey,
    authority: &Pubkey,
    subject: &Pubkey,
    native: &[Pubkey],
    other: &[&str],
) -> Instruction {
    let mut data = IX_SET_CONTROLLERS.to_vec();
    data.extend_from_slice(&(native.len() as u32).to_le_bytes());
    for key in native {
        data.extend_from_slice(key.as_ref());
    }
    data.extend_from_slice(&(other.len() as u32).to_le_bytes());
    for s in other {
        put_str(&mut data, s);
    }
    Instruction {
        program_id: program_id(),
        accounts: mutate_metas(payer, authority, subject),
        data,
    }
}

fn deactivate_ix(payer: &Pubkey, authority: &Pubkey, subject: &Pubkey) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: mutate_metas(payer, authority, subject),
        data: IX_DEACTIVATE.to_vec(),
    }
}

/// Sends one instruction; on failure returns `"{err:?} logs: {logs:?}"`.
fn send(
    svm: &mut LiteSVM,
    ix: Instruction,
    payer: &Keypair,
    extra_signers: &[&Keypair],
) -> Result<(), String> {
    send_meta(svm, ix, payer, extra_signers).map(|_| ())
}

fn send_meta(
    svm: &mut LiteSVM,
    ix: Instruction,
    payer: &Keypair,
    extra_signers: &[&Keypair],
) -> Result<litesvm::types::TransactionMetadata, String> {
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash);
    let mut signers: Vec<&Keypair> = vec![payer];
    for s in extra_signers {
        if s.pubkey() != payer.pubkey() {
            signers.push(s);
        }
    }
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &signers)
        .map_err(|e| e.to_string())?;
    svm.send_transaction(tx)
        .map_err(|e| format!("{:?} logs: {:?}", e.err, e.meta.logs))
}

fn assert_custom_err(res: Result<(), String>, code: u32, what: &str) {
    let err = res.expect_err(&format!("expected {what} ({code})"));
    assert!(
        err.contains(&format!("Custom({code})")),
        "expected {what} (Custom({code})), got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_initialize_creates_generative_default() {
    let mut svm = setup();
    let subject = Keypair::new();
    svm.airdrop(&subject.pubkey(), AIRDROP).unwrap();

    send(
        &mut svm,
        initialize_ix(&subject.pubkey(), &subject.pubkey()),
        &subject,
        &[],
    )
    .unwrap();

    let pda = did_pda(&subject.pubkey());
    let did = decode(&svm, &pda);
    assert_eq!(did.version, 1);
    assert_eq!(did.subject, subject.pubkey().to_bytes());
    assert!(!did.deactivated);
    assert_eq!(did.verification_methods.len(), 1);
    let vm = &did.verification_methods[0];
    assert_eq!(vm.fragment, "default");
    assert_eq!(vm.method_type, VM_TYPE_ED25519);
    assert_eq!(vm.flags, VM_FLAGS_DEFAULT);
    assert_eq!(vm.key_data, subject.pubkey().to_bytes().to_vec());
    assert!(did.services.is_empty());
    assert!(did.native_controllers.is_empty());

    // Exact-size account, byte-for-byte the documented generative layout.
    let account = svm.get_account(&pda).unwrap();
    assert_eq!(account.data.len(), INITIAL_SPACE);
    let bump =
        Pubkey::find_program_address(&[b"bio-did", subject.pubkey().as_ref()], &program_id()).1;
    let mut expected = Vec::with_capacity(INITIAL_SPACE);
    expected.extend_from_slice(&ACCOUNT_DISCRIMINATOR);
    expected.extend_from_slice(&1u64.to_le_bytes()); // version
    expected.push(bump);
    expected.extend_from_slice(subject.pubkey().as_ref()); // subject
    expected.push(0); // deactivated
    expected.extend_from_slice(&account.data[50..58]); // updated_at (clock-dependent)
    expected.extend_from_slice(&0u32.to_le_bytes()); // native_controllers
    expected.extend_from_slice(&0u32.to_le_bytes()); // other_controllers
    expected.extend_from_slice(&1u32.to_le_bytes()); // verification_methods
    expected.extend_from_slice(&7u32.to_le_bytes());
    expected.extend_from_slice(b"default");
    expected.push(VM_TYPE_ED25519);
    expected.extend_from_slice(&VM_FLAGS_DEFAULT.to_le_bytes());
    expected.extend_from_slice(&32u32.to_le_bytes());
    expected.extend_from_slice(subject.pubkey().as_ref());
    expected.extend_from_slice(&0u32.to_le_bytes()); // services
    assert_eq!(
        account.data, expected,
        "generative account bytes must match the spec layout"
    );

    // Double-initialize must fail (account exists).
    assert!(send(
        &mut svm,
        initialize_ix(&subject.pubkey(), &subject.pubkey()),
        &subject,
        &[],
    )
    .is_err());
}

#[test]
fn test_sponsored_initialize_grants_no_control_to_payer() {
    let mut svm = setup();
    let sponsor = Keypair::new();
    let subject = Keypair::new();
    svm.airdrop(&sponsor.pubkey(), AIRDROP).unwrap();

    // Sponsor pays; subject never signs.
    send(
        &mut svm,
        initialize_ix(&sponsor.pubkey(), &subject.pubkey()),
        &sponsor,
        &[],
    )
    .unwrap();
    let did = decode(&svm, &did_pda(&subject.pubkey()));
    assert_eq!(did.subject, subject.pubkey().to_bytes());

    // Sponsor cannot mutate: not an authority.
    let intruder_key = Keypair::new();
    let res = send(
        &mut svm,
        add_vm_ix(
            &sponsor.pubkey(),
            &sponsor.pubkey(),
            &subject.pubkey(),
            "intruder",
            VM_TYPE_ED25519,
            VM_FLAG_AUTHENTICATION,
            intruder_key.pubkey().as_ref(),
        ),
        &sponsor,
        &[],
    );
    assert_custom_err(res, 6000, "Unauthorized");
}

#[test]
fn test_add_verification_method_and_validation() {
    let mut svm = setup();
    let subject = Keypair::new();
    svm.airdrop(&subject.pubkey(), AIRDROP).unwrap();
    send(
        &mut svm,
        initialize_ix(&subject.pubkey(), &subject.pubkey()),
        &subject,
        &[],
    )
    .unwrap();
    let pda = did_pda(&subject.pubkey());
    let s = subject.pubkey();

    // Happy path: rotation key with authentication + capabilityInvocation.
    let rotation = Keypair::new();
    send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "rotation-1",
            VM_TYPE_ED25519,
            VM_FLAG_AUTHENTICATION | VM_FLAG_CAPABILITY_INVOCATION,
            rotation.pubkey().as_ref(),
        ),
        &subject,
        &[],
    )
    .unwrap();
    let did = decode(&svm, &pda);
    assert_eq!(did.version, 2);
    assert_eq!(did.verification_methods.len(), 2);
    assert_eq!(did.verification_methods[1].fragment, "rotation-1");

    // Duplicate fragment.
    let res = send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "rotation-1",
            VM_TYPE_ED25519,
            VM_FLAG_AUTHENTICATION,
            Keypair::new().pubkey().as_ref(),
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6003, "FragmentAlreadyInUse");

    // Wrong key length for type.
    let res = send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "short",
            VM_TYPE_ED25519,
            VM_FLAG_AUTHENTICATION,
            &[7u8; 16],
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6009, "InvalidKeyLength");

    // X25519 cannot authenticate.
    let res = send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "xkey",
            VM_TYPE_X25519,
            VM_FLAG_AUTHENTICATION,
            &[7u8; 32],
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6010, "InvalidFlags");

    // capabilityInvocation restricted to Ed25519.
    let res = send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "pq",
            VM_TYPE_DILITHIUM5,
            VM_FLAG_CAPABILITY_INVOCATION,
            &[7u8; 2592],
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6010, "InvalidFlags");

    // Valid post-quantum assertion method.
    send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "pq",
            VM_TYPE_DILITHIUM5,
            VM_FLAG_ASSERTION,
            &[7u8; 2592],
        ),
        &subject,
        &[],
    )
    .unwrap();
    let did = decode(&svm, &pda);
    assert_eq!(did.verification_methods.len(), 3);
    assert_eq!(did.verification_methods[2].key_data.len(), 2592);
    assert_eq!(
        account_len(&svm, &pda),
        INITIAL_SPACE + 4 + 10 + 1 + 2 + 4 + 32 + 4 + 2 + 1 + 2 + 4 + 2592
    );

    // Bad fragment charset.
    let res = send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "no spaces!",
            VM_TYPE_ED25519,
            VM_FLAG_AUTHENTICATION,
            Keypair::new().pubkey().as_ref(),
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6002, "InvalidFragment");
}

#[test]
fn test_key_rotation_and_protection() {
    let mut svm = setup();
    let subject = Keypair::new();
    let rotation = Keypair::new();
    svm.airdrop(&subject.pubkey(), AIRDROP).unwrap();
    svm.airdrop(&rotation.pubkey(), AIRDROP).unwrap();
    send(
        &mut svm,
        initialize_ix(&subject.pubkey(), &subject.pubkey()),
        &subject,
        &[],
    )
    .unwrap();
    let pda = did_pda(&subject.pubkey());
    let s = subject.pubkey();
    let r = rotation.pubkey();

    send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "rotation-1",
            VM_TYPE_ED25519,
            VM_FLAG_AUTHENTICATION | VM_FLAG_CAPABILITY_INVOCATION,
            r.as_ref(),
        ),
        &subject,
        &[],
    )
    .unwrap();

    // The new authority may NOT remove the protected #default method...
    let res = send(
        &mut svm,
        remove_vm_ix(&r, &r, &s, "default"),
        &rotation,
        &[],
    );
    assert_custom_err(res, 6011, "ProtectedVerificationMethod");

    // ...but the subject itself may (another authority remains): true rotation.
    send(&mut svm, remove_vm_ix(&s, &s, &s, "default"), &subject, &[]).unwrap();
    let did = decode(&svm, &pda);
    assert_eq!(did.verification_methods.len(), 1);
    assert_eq!(did.verification_methods[0].fragment, "rotation-1");

    // The rotated-out subject key no longer has authority.
    let res = send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "come-back",
            VM_TYPE_ED25519,
            VM_FLAG_AUTHENTICATION,
            s.as_ref(),
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6000, "Unauthorized");

    // Removing the final authority is impossible.
    let res = send(
        &mut svm,
        remove_vm_ix(&r, &r, &s, "rotation-1"),
        &rotation,
        &[],
    );
    assert_custom_err(res, 6012, "LastAuthority");
}

#[test]
fn test_set_flags_rules() {
    let mut svm = setup();
    let subject = Keypair::new();
    svm.airdrop(&subject.pubkey(), AIRDROP).unwrap();
    send(
        &mut svm,
        initialize_ix(&subject.pubkey(), &subject.pubkey()),
        &subject,
        &[],
    )
    .unwrap();
    let pda = did_pda(&subject.pubkey());
    let s = subject.pubkey();

    // Stripping capabilityInvocation from the sole authority must fail.
    let res = send(
        &mut svm,
        set_flags_ix(
            &s,
            &s,
            "default",
            VM_FLAG_AUTHENTICATION | VM_FLAG_PROTECTED,
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6012, "LastAuthority");

    // Unknown flag bits rejected.
    let res = send(
        &mut svm,
        set_flags_ix(&s, &s, "default", VM_FLAGS_DEFAULT | (1 << 12)),
        &subject,
        &[],
    );
    assert_custom_err(res, 6010, "InvalidFlags");

    // Subject (own key) may adjust its own protected method's relationships.
    send(
        &mut svm,
        set_flags_ix(
            &s,
            &s,
            "default",
            VM_FLAG_AUTHENTICATION
                | VM_FLAG_ASSERTION
                | VM_FLAG_CAPABILITY_INVOCATION
                | VM_FLAG_PROTECTED,
        ),
        &subject,
        &[],
    )
    .unwrap();
    let did = decode(&svm, &pda);
    assert_eq!(did.verification_methods[0].flags & VM_FLAG_KEY_AGREEMENT, 0);
    assert_eq!(did.version, 2);
}

#[test]
fn test_services_and_controllers() {
    let mut svm = setup();
    let subject = Keypair::new();
    svm.airdrop(&subject.pubkey(), AIRDROP).unwrap();
    send(
        &mut svm,
        initialize_ix(&subject.pubkey(), &subject.pubkey()),
        &subject,
        &[],
    )
    .unwrap();
    let pda = did_pda(&subject.pubkey());
    let s = subject.pubkey();

    send(
        &mut svm,
        add_service_ix(
            &s,
            &s,
            &s,
            "metadata",
            "BioMetadata",
            "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        ),
        &subject,
        &[],
    )
    .unwrap();
    let did = decode(&svm, &pda);
    assert_eq!(did.services.len(), 1);
    assert_eq!(did.services[0].service_type, "BioMetadata");

    // Fragment collision with a verification method fragment is rejected too.
    let res = send(
        &mut svm,
        add_service_ix(
            &s,
            &s,
            &s,
            "default",
            "IPFSStorage",
            "https://ipfs.example.org/api",
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6003, "FragmentAlreadyInUse");

    // Endpoint with whitespace rejected.
    let res = send(
        &mut svm,
        add_service_ix(&s, &s, &s, "bad", "BioMetadata", "not a uri"),
        &subject,
        &[],
    );
    assert_custom_err(res, 6014, "InvalidServiceValue");

    // Controllers.
    let lab = Keypair::new().pubkey();
    send(
        &mut svm,
        set_controllers_ix(&s, &s, &s, &[lab], &["did:web:lab.example.org"]),
        &subject,
        &[],
    )
    .unwrap();
    let did = decode(&svm, &pda);
    assert_eq!(did.native_controllers, vec![lab.to_bytes()]);
    assert_eq!(
        did.other_controllers,
        vec!["did:web:lab.example.org".to_string()]
    );

    // Self-reference and did:bio-in-other are rejected.
    let res = send(
        &mut svm,
        set_controllers_ix(&s, &s, &s, &[s], &[]),
        &subject,
        &[],
    );
    assert_custom_err(res, 6013, "InvalidController (self)");
    let res = send(
        &mut svm,
        set_controllers_ix(
            &s,
            &s,
            &s,
            &[],
            &["did:bio:5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"],
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6013, "InvalidController (did:bio in other)");

    // Remove service refunds rent and shrinks the account.
    let before = svm.get_account(&pda).unwrap();
    send(
        &mut svm,
        remove_service_ix(&s, &s, &s, "metadata"),
        &subject,
        &[],
    )
    .unwrap();
    let after = svm.get_account(&pda).unwrap();
    assert!(after.data.len() < before.data.len());
    assert!(
        after.lamports < before.lamports,
        "shrink should refund rent"
    );
    let did = decode(&svm, &pda);
    assert!(did.services.is_empty());
}

#[test]
fn test_controllers_replacement_grows_and_shrinks() {
    let mut svm = setup();
    let subject = Keypair::new();
    svm.airdrop(&subject.pubkey(), AIRDROP).unwrap();
    send(
        &mut svm,
        initialize_ix(&subject.pubkey(), &subject.pubkey()),
        &subject,
        &[],
    )
    .unwrap();
    let pda = did_pda(&subject.pubkey());
    let s = subject.pubkey();

    // Max out both controller sets.
    let natives: Vec<Pubkey> = (0..8).map(|_| Keypair::new().pubkey()).collect();
    let other_strings: Vec<String> = (0..8)
        .map(|i| format!("did:web:lab{i}.example.org"))
        .collect();
    let others: Vec<&str> = other_strings.iter().map(|s| s.as_str()).collect();
    send(
        &mut svm,
        set_controllers_ix(&s, &s, &s, &natives, &others),
        &subject,
        &[],
    )
    .unwrap();
    let did = decode(&svm, &pda);
    assert_eq!(did.native_controllers.len(), 8);
    assert_eq!(did.other_controllers.len(), 8);
    let large = account_len(&svm, &pda);

    // Ninth entries are rejected.
    let nine_native: Vec<Pubkey> = (0..9).map(|_| Keypair::new().pubkey()).collect();
    let res = send(
        &mut svm,
        set_controllers_ix(&s, &s, &s, &nine_native, &[]),
        &subject,
        &[],
    );
    assert_custom_err(res, 6008, "TooManyControllers");

    // Shrink back to empty; version keeps marching, size returns to initial.
    send(
        &mut svm,
        set_controllers_ix(&s, &s, &s, &[], &[]),
        &subject,
        &[],
    )
    .unwrap();
    let did = decode(&svm, &pda);
    assert!(did.native_controllers.is_empty() && did.other_controllers.is_empty());
    assert_eq!(account_len(&svm, &pda), INITIAL_SPACE);
    assert!(account_len(&svm, &pda) < large);
    assert_eq!(did.version, 3);
}

#[test]
fn test_deactivate_is_permanent_tombstone() {
    let mut svm = setup();
    let subject = Keypair::new();
    svm.airdrop(&subject.pubkey(), AIRDROP).unwrap();
    send(
        &mut svm,
        initialize_ix(&subject.pubkey(), &subject.pubkey()),
        &subject,
        &[],
    )
    .unwrap();
    let pda = did_pda(&subject.pubkey());
    let s = subject.pubkey();

    // Add some content first so the tombstone actually shrinks.
    send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "extra",
            VM_TYPE_ED25519,
            VM_FLAG_AUTHENTICATION,
            Keypair::new().pubkey().as_ref(),
        ),
        &subject,
        &[],
    )
    .unwrap();

    let balance_before = svm.get_balance(&subject.pubkey()).unwrap();
    send(&mut svm, deactivate_ix(&s, &s, &s), &subject, &[]).unwrap();

    let account = svm.get_account(&pda).unwrap();
    assert_eq!(account.data.len(), TOMBSTONE_SPACE);
    let did = decode(&svm, &pda);
    assert!(did.deactivated);
    assert!(did.verification_methods.is_empty());
    assert!(did.services.is_empty());
    // Rent refund exceeded the transaction fee.
    assert!(svm.get_balance(&subject.pubkey()).unwrap() > balance_before - 5000);

    // Every further mutation is rejected forever.
    let res = send(
        &mut svm,
        add_vm_ix(
            &s,
            &s,
            &s,
            "revive",
            VM_TYPE_ED25519,
            VM_FLAG_AUTHENTICATION,
            s.as_ref(),
        ),
        &subject,
        &[],
    );
    assert_custom_err(res, 6001, "DidDeactivated");
    svm.expire_blockhash();
    let res = send(&mut svm, deactivate_ix(&s, &s, &s), &subject, &[]);
    assert_custom_err(res, 6001, "DidDeactivated");
}

#[test]
fn test_events_wire_format() {
    let mut svm = setup();
    let subject = Keypair::new();
    svm.airdrop(&subject.pubkey(), AIRDROP).unwrap();
    let pda = did_pda(&subject.pubkey());

    let assert_event = |meta: &litesvm::types::TransactionMetadata, disc: [u8; 8], version: u64| {
        use base64::Engine;
        let payload = meta
            .logs
            .iter()
            .find_map(|l| l.strip_prefix("Program data: "))
            .expect("expected a `Program data:` event log");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .unwrap();
        assert_eq!(
            bytes.len(),
            80,
            "event = 8-byte discriminator + 32 + 32 + 8"
        );
        assert_eq!(bytes[0..8], disc, "event discriminator");
        assert_eq!(bytes[8..40], pda.to_bytes(), "event.did_account");
        assert_eq!(bytes[40..72], subject.pubkey().to_bytes(), "event.subject");
        assert_eq!(bytes[72..80], version.to_le_bytes(), "event.version");
    };

    let meta = send_meta(
        &mut svm,
        initialize_ix(&subject.pubkey(), &subject.pubkey()),
        &subject,
        &[],
    )
    .unwrap();
    assert_event(&meta, [125, 40, 26, 220, 241, 180, 151, 84], 1); // DidInitialized

    let s = subject.pubkey();
    let meta = send_meta(
        &mut svm,
        add_service_ix(
            &s,
            &s,
            &s,
            "metadata",
            "BioMetadata",
            "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        ),
        &subject,
        &[],
    )
    .unwrap();
    assert_event(&meta, [127, 241, 158, 225, 33, 224, 88, 208], 2); // DidModified

    let meta = send_meta(&mut svm, deactivate_ix(&s, &s, &s), &subject, &[]).unwrap();
    assert_event(&meta, [6, 124, 31, 30, 191, 92, 197, 57], 3); // DidDeactivated
}
