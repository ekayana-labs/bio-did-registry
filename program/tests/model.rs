//! Random instruction sequences against a model of the rules.
//!
//! Each case runs a sequence of updates on two DIDs, signed by a handful of
//! keys, some through the other DID as a native controller. The model is a
//! plain Rust rendering of the rules in the order the program checks them.
//! After every instruction the program's result must match the model's,
//! error code included, and the decoded account must equal the model's
//! document. That exercises the in-place editing over long histories.
//!
//! Build the program first with
//! `cargo build-sbf --manifest-path program/Cargo.toml`.

use std::path::PathBuf;

use bio_did_registry::{client, state};
use litesvm::LiteSVM;
use proptest::prelude::*;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

const SIGNERS: usize = 4;
const FRAGMENTS: [&str; 8] = [
    "default",
    "a",
    "b",
    "rot",
    "pq",
    "svc",
    "bad frag",
    "f-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
];
const SERVICE_TYPES: [&str; 5] = [
    "BioMetadata",
    "T",
    "has space",
    "",
    "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt",
];
/// Valid endpoints of four lengths, so updates both grow and shrink, then
/// two invalid ones.
const ENDPOINTS: [&str; 6] = [
    "x",
    "ipfs://a",
    "https://example.org/data",
    "https://example.org/a/much/longer/path/to/the/same/dataset",
    "",
    "not a uri",
];
const EXTERNALS: [&str; 5] = [
    "did:web:lab.example.org",
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "did:bio:5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
    "did:web",
    "did:Web:x",
];
const FLAGS: [u16; 10] = [
    state::VM_FLAG_AUTHENTICATION,
    state::VM_FLAG_ASSERTION,
    state::VM_FLAG_KEY_AGREEMENT,
    state::VM_FLAG_CAPABILITY_INVOCATION,
    state::VM_FLAG_CAPABILITY_INVOCATION | state::VM_FLAG_PROTECTED,
    state::VM_FLAG_AUTHENTICATION | state::VM_FLAG_PROTECTED,
    state::VM_FLAGS_DEFAULT,
    state::VM_FLAG_ASSERTION | state::VM_FLAG_CAPABILITY_DELEGATION,
    1 << 12,
    0,
];

#[derive(Clone, Debug)]
enum Key {
    /// One of the signing keypairs.
    Signer(usize),
    /// A key nobody here holds.
    Fresh(u8),
    /// A program address, off the curve.
    OffCurve(u8),
    /// Bytes of the given fill, the right length for the type or one short.
    Bytes(u8, bool),
}

#[derive(Clone, Debug)]
enum Op {
    AddVm {
        fragment: usize,
        method_type: u8,
        flags: usize,
        key: Key,
    },
    RemoveVm {
        fragment: usize,
    },
    SetFlags {
        fragment: usize,
        flags: usize,
    },
    AddService {
        fragment: usize,
        service_type: usize,
        endpoint: usize,
    },
    UpdateService {
        fragment: usize,
        service_type: usize,
        endpoint: usize,
    },
    RemoveService {
        fragment: usize,
    },
    SetControllers {
        natives: Vec<usize>,
        externals: Vec<usize>,
    },
    Deactivate,
}

/// One step: an update on DID `did`, signed by `signer`, with the registry
/// account of DID `via` appended when it is set.
#[derive(Clone, Debug)]
struct Step {
    did: usize,
    signer: usize,
    via: Option<usize>,
    op: Op,
}

#[derive(Clone, Debug, PartialEq)]
struct Vm {
    fragment: Vec<u8>,
    method_type: u8,
    flags: u16,
    key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
struct Svc {
    fragment: Vec<u8>,
    service_type: Vec<u8>,
    endpoint: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
struct Did {
    version: u64,
    subject: [u8; 32],
    deactivated: bool,
    natives: Vec<[u8; 32]>,
    others: Vec<Vec<u8>>,
    vms: Vec<Vm>,
    services: Vec<Svc>,
}

/// An instruction's outcome, as the program reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Custom(u32),
    Other(String),
}

fn decode(data: &[u8]) -> Did {
    let mut r = Cursor { data, at: 8 };
    let version = u64::from_le_bytes(r.bytes(8).try_into().unwrap());
    r.bytes(1);
    let subject: [u8; 32] = r.bytes(32).try_into().unwrap();
    let deactivated = r.bytes(1)[0] == 1;
    r.bytes(8);
    let natives = (0..r.u32())
        .map(|_| r.bytes(32).try_into().unwrap())
        .collect();
    let others = (0..r.u32()).map(|_| r.prefixed()).collect();
    let vms = (0..r.u32())
        .map(|_| Vm {
            fragment: r.prefixed(),
            method_type: r.bytes(1)[0],
            flags: u16::from_le_bytes(r.bytes(2).try_into().unwrap()),
            key: r.prefixed(),
        })
        .collect();
    let services = (0..r.u32())
        .map(|_| Svc {
            fragment: r.prefixed(),
            service_type: r.prefixed(),
            endpoint: r.prefixed(),
        })
        .collect();
    assert_eq!(r.at, data.len(), "the account is exact-size");
    Did {
        version,
        subject,
        deactivated,
        natives,
        others,
        vms,
        services,
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let out = self.data[self.at..self.at + n].to_vec();
        self.at += n;
        out
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.bytes(4).try_into().unwrap())
    }
    fn prefixed(&mut self) -> Vec<u8> {
        let n = self.u32() as usize;
        self.bytes(n)
    }
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

fn key_len(method_type: u8) -> Option<usize> {
    match method_type {
        0 | 1 => Some(32),
        2 => Some(33),
        3 => Some(2592),
        _ => None,
    }
}

fn is_authority(vm: &Vm) -> bool {
    vm.method_type == 0 && vm.flags & state::VM_FLAG_CAPABILITY_INVOCATION != 0
}

fn valid_fragment(f: &[u8]) -> bool {
    (1..=32).contains(&f.len())
        && f.iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(b))
}

fn printable(v: &[u8], max: usize) -> bool {
    !v.is_empty() && v.len() <= max && v.iter().all(u8::is_ascii_graphic)
}

fn flags_allowed(method_type: u8, flags: u16) -> bool {
    use state::*;
    flags & !VM_VALID_MASK == 0
        && (flags & (VM_FLAG_CAPABILITY_INVOCATION | VM_FLAG_PROTECTED) == 0 || method_type == 0)
        && (flags & VM_FLAG_PROTECTED == 0 || flags & VM_FLAG_CAPABILITY_INVOCATION != 0)
        && (method_type != 1 || flags & VM_RELATIONSHIP_MASK & !VM_FLAG_KEY_AGREEMENT == 0)
        && (method_type != 3 || flags & VM_FLAG_KEY_AGREEMENT == 0)
}

fn external_allowed(value: &[u8]) -> bool {
    let Some(rest) = printable(value, 128)
        .then_some(value)
        .and_then(|v| v.strip_prefix(b"did:"))
    else {
        return false;
    };
    let Some(colon) = rest.iter().position(|b| *b == b':') else {
        return false;
    };
    let (method, id) = (&rest[..colon], &rest[colon + 1..]);
    !method.is_empty()
        && method != b"bio"
        && method
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !id.is_empty()
}

struct World {
    svm: LiteSVM,
    signers: Vec<Keypair>,
    subjects: [[u8; 32]; 2],
    /// What a native controller choice names, the signer keys and then the
    /// two subjects.
    natives: Vec<[u8; 32]>,
    docs: [Did; 2],
}

impl World {
    fn new() -> Self {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/bio_did_registry.so");
        let so = std::fs::read(path)
            .expect("run cargo build-sbf --manifest-path program/Cargo.toml first");
        let mut svm = LiteSVM::new();
        svm.add_program(
            Pubkey::new_from_array(*bio_did_registry::ID.as_array()),
            &so,
        )
        .unwrap();
        let signers: Vec<Keypair> = (0..SIGNERS as u8)
            .map(|i| Keypair::new_from_array([i + 1; 32]))
            .collect();
        for k in &signers {
            svm.airdrop(&k.pubkey(), 1_000_000_000_000).unwrap();
        }
        let k0 = signers[0].pubkey().to_bytes();
        let k1 = signers[1].pubkey().to_bytes();
        let subjects = [k0, state::owned_subject(&k1, 7)];
        let mut natives: Vec<[u8; 32]> = signers.iter().map(|k| k.pubkey().to_bytes()).collect();
        natives.extend(subjects);
        let mut world = World {
            svm,
            signers,
            subjects,
            natives,
            docs: [Did::fresh(subjects[0], k0), Did::fresh(subjects[1], k1)],
        };
        world.send(0, client::initialize(&k0, &k0)).unwrap();
        world
            .send(1, client::initialize_owned(&k1, &k1, 7))
            .unwrap();
        world
    }

    fn send(&mut self, signer: usize, ix: client::Instruction) -> Result<(), Outcome> {
        let ix = Instruction {
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
        };
        self.svm.expire_blockhash();
        let payer = &self.signers[signer];
        let msg =
            Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &self.svm.latest_blockhash());
        let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[payer]).unwrap();
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| {
            let text = format!("{:?}", e.err);
            match text
                .split("Custom(")
                .nth(1)
                .and_then(|r| r.split(')').next())
                .and_then(|c| c.parse().ok())
            {
                Some(code) => Outcome::Custom(code),
                None => Outcome::Other(text),
            }
        })
    }

    fn key(&self, key: &Key, method_type: u8) -> Vec<u8> {
        let len = key_len(method_type).unwrap_or(32);
        match key {
            Key::Signer(i) => self.signers[*i % SIGNERS].pubkey().to_bytes().to_vec(),
            Key::Fresh(seed) => Keypair::new_from_array([*seed; 32])
                .pubkey()
                .to_bytes()
                .to_vec(),
            Key::OffCurve(seed) => state::owned_subject(&[*seed; 32], 1).to_vec(),
            Key::Bytes(fill, short) => {
                let mut key = vec![*fill; len - usize::from(*short)];
                if let Some(first) = key.first_mut() {
                    *first = 2 + (fill & 1);
                }
                key
            }
        }
    }

    /// The model's verdict on the signer's authority over DID `did`.
    fn authorize(&self, did: usize, signer: &[u8; 32], via: Option<usize>) -> Result<(), u32> {
        let doc = &self.docs[did];
        if doc.deactivated {
            return Err(6001);
        }
        if doc
            .vms
            .iter()
            .any(|vm| is_authority(vm) && vm.key == signer)
        {
            return Ok(());
        }
        let parent = &self.docs[via.ok_or(6000u32)?];
        if !doc.natives.contains(&parent.subject)
            || parent.deactivated
            || !parent
                .vms
                .iter()
                .any(|vm| is_authority(vm) && vm.key == signer)
        {
            return Err(6000);
        }
        Ok(())
    }

    /// Applies `step` to the model and returns the code the program must
    /// report, or `None` when it must succeed.
    fn model(&mut self, step: &Step, key: &[u8]) -> Option<u32> {
        let signer = self.signers[step.signer].pubkey().to_bytes();
        let fragment = |i: &usize| FRAGMENTS[*i].as_bytes().to_vec();
        if let Err(code) = self.authorize(step.did, &signer, step.via) {
            return Some(code);
        }
        let choices = self.natives.clone();
        let doc = &mut self.docs[step.did];
        let taken = |doc: &Did, f: &[u8]| {
            doc.vms.iter().any(|vm| vm.fragment == f)
                || doc.services.iter().any(|s| s.fragment == f)
        };
        let result: Result<(), u32> = (|| match &step.op {
            Op::AddVm {
                fragment: f,
                method_type,
                flags,
                ..
            } => {
                let (f, flags) = (fragment(f), FLAGS[*flags]);
                if doc.vms.len() >= 16 {
                    return Err(6006);
                }
                if !valid_fragment(&f) {
                    return Err(6002);
                }
                if taken(doc, &f) {
                    return Err(6003);
                }
                if f == b"default" {
                    return Err(6002);
                }
                if Some(key.len()) != key_len(*method_type) {
                    return Err(6009);
                }
                if !flags_allowed(*method_type, flags) {
                    return Err(6010);
                }
                if flags & state::VM_FLAG_PROTECTED != 0 && key != signer {
                    return Err(6011);
                }
                let on_curve =
                    || pinocchio::Address::new_from_array(key.try_into().unwrap()).is_on_curve();
                if *method_type == 0 && key != signer && !on_curve() {
                    return Err(6018);
                }
                if *method_type == 2 && !matches!(key[0], 2 | 3) {
                    return Err(6018);
                }
                doc.vms.push(Vm {
                    fragment: f,
                    method_type: *method_type,
                    flags,
                    key: key.to_vec(),
                });
                Ok(())
            }
            Op::RemoveVm { fragment: f } => {
                let f = fragment(f);
                let at = doc
                    .vms
                    .iter()
                    .position(|vm| vm.fragment == f)
                    .ok_or(6004u32)?;
                let vm = &doc.vms[at];
                if vm.flags & state::VM_FLAG_PROTECTED != 0 && vm.key != signer {
                    return Err(6011);
                }
                if is_authority(vm) && doc.vms.iter().filter(|vm| is_authority(vm)).count() < 2 {
                    return Err(6012);
                }
                doc.vms.remove(at);
                Ok(())
            }
            Op::SetFlags { fragment: f, flags } => {
                let (f, flags) = (fragment(f), FLAGS[*flags]);
                let at = doc
                    .vms
                    .iter()
                    .position(|vm| vm.fragment == f)
                    .ok_or(6004u32)?;
                let vm = &doc.vms[at];
                if (vm.flags | flags) & state::VM_FLAG_PROTECTED != 0 && vm.key != signer {
                    return Err(6011);
                }
                if !flags_allowed(vm.method_type, flags) {
                    return Err(6010);
                }
                if is_authority(vm)
                    && flags & state::VM_FLAG_CAPABILITY_INVOCATION == 0
                    && doc.vms.iter().filter(|vm| is_authority(vm)).count() < 2
                {
                    return Err(6012);
                }
                doc.vms[at].flags = flags;
                Ok(())
            }
            Op::AddService {
                fragment: f,
                service_type,
                endpoint,
            } => {
                let f = fragment(f);
                if doc.services.len() >= 16 {
                    return Err(6007);
                }
                if !valid_fragment(&f) {
                    return Err(6002);
                }
                if taken(doc, &f) {
                    return Err(6003);
                }
                if f == b"default" {
                    return Err(6002);
                }
                let (t, e) = (
                    SERVICE_TYPES[*service_type].as_bytes(),
                    ENDPOINTS[*endpoint].as_bytes(),
                );
                if !printable(t, 64) || !printable(e, 512) {
                    return Err(6014);
                }
                doc.services.push(Svc {
                    fragment: f,
                    service_type: t.to_vec(),
                    endpoint: e.to_vec(),
                });
                Ok(())
            }
            Op::UpdateService {
                fragment: f,
                service_type,
                endpoint,
            } => {
                let f = fragment(f);
                let at = doc
                    .services
                    .iter()
                    .position(|s| s.fragment == f)
                    .ok_or(6005u32)?;
                let (t, e) = (
                    SERVICE_TYPES[*service_type].as_bytes(),
                    ENDPOINTS[*endpoint].as_bytes(),
                );
                if !printable(t, 64) || !printable(e, 512) {
                    return Err(6014);
                }
                doc.services[at].service_type = t.to_vec();
                doc.services[at].endpoint = e.to_vec();
                Ok(())
            }
            Op::RemoveService { fragment: f } => {
                let f = fragment(f);
                let at = doc
                    .services
                    .iter()
                    .position(|s| s.fragment == f)
                    .ok_or(6005u32)?;
                doc.services.remove(at);
                Ok(())
            }
            Op::SetControllers { natives, externals } => {
                if natives.len() > 8 || externals.len() > 8 {
                    return Err(6008);
                }
                let natives: Vec<[u8; 32]> = natives.iter().map(|i| choices[*i]).collect();
                for (i, n) in natives.iter().enumerate() {
                    if *n == doc.subject || natives[..i].contains(n) {
                        return Err(6013);
                    }
                }
                let externals: Vec<Vec<u8>> = externals
                    .iter()
                    .map(|i| EXTERNALS[*i].as_bytes().to_vec())
                    .collect();
                for (i, e) in externals.iter().enumerate() {
                    if !external_allowed(e) || externals[..i].contains(e) {
                        return Err(6013);
                    }
                }
                doc.natives = natives;
                doc.others = externals;
                Ok(())
            }
            Op::Deactivate => {
                doc.deactivated = true;
                doc.natives.clear();
                doc.others.clear();
                doc.vms.clear();
                doc.services.clear();
                Ok(())
            }
        })();
        match result {
            Ok(()) => {
                doc.version += 1;
                None
            }
            Err(code) => Some(code),
        }
    }
}

impl Did {
    fn fresh(subject: [u8; 32], key: [u8; 32]) -> Self {
        Did {
            version: 1,
            subject,
            deactivated: false,
            natives: Vec::new(),
            others: Vec::new(),
            vms: vec![Vm {
                fragment: b"default".to_vec(),
                method_type: 0,
                flags: state::VM_FLAGS_DEFAULT,
                key: key.to_vec(),
            }],
            services: Vec::new(),
        }
    }
}

fn instruction(world: &World, step: &Step, key: &[u8]) -> client::Instruction {
    let signer = world.signers[step.signer].pubkey().to_bytes();
    let subject = world.subjects[step.did];
    let s = &signer;
    let ix = match &step.op {
        Op::AddVm {
            fragment,
            method_type,
            flags,
            ..
        } => client::add_verification_method(
            s,
            s,
            &subject,
            FRAGMENTS[*fragment],
            *method_type,
            FLAGS[*flags],
            key,
        ),
        Op::RemoveVm { fragment } => {
            client::remove_verification_method(s, s, &subject, FRAGMENTS[*fragment])
        }
        Op::SetFlags { fragment, flags } => {
            client::set_verification_method_flags(s, &subject, FRAGMENTS[*fragment], FLAGS[*flags])
        }
        Op::AddService {
            fragment,
            service_type,
            endpoint,
        } => client::add_service(
            s,
            s,
            &subject,
            FRAGMENTS[*fragment],
            SERVICE_TYPES[*service_type],
            ENDPOINTS[*endpoint],
        ),
        Op::UpdateService {
            fragment,
            service_type,
            endpoint,
        } => client::update_service(
            s,
            s,
            &subject,
            FRAGMENTS[*fragment],
            SERVICE_TYPES[*service_type],
            ENDPOINTS[*endpoint],
        ),
        Op::RemoveService { fragment } => {
            client::remove_service(s, s, &subject, FRAGMENTS[*fragment])
        }
        Op::SetControllers { natives, externals } => {
            let natives: Vec<[u8; 32]> = natives.iter().map(|i| world.natives[*i]).collect();
            let externals: Vec<&str> = externals.iter().map(|i| EXTERNALS[*i]).collect();
            client::set_controllers(s, s, &subject, &natives, &externals)
        }
        Op::Deactivate => client::deactivate(s, s, &subject),
    };
    match step.via {
        Some(via) => ix.via_controller(&world.subjects[via]),
        None => ix,
    }
}

fn key() -> impl Strategy<Value = Key> {
    prop_oneof![
        (0..SIGNERS).prop_map(Key::Signer),
        any::<u8>().prop_map(Key::Fresh),
        any::<u8>().prop_map(Key::OffCurve),
        (any::<u8>(), proptest::bool::weighted(0.1))
            .prop_map(|(fill, short)| Key::Bytes(fill, short)),
    ]
}

/// Mostly the valid fragments other than `default`, sometimes any.
fn fragment() -> impl Strategy<Value = usize> {
    prop_oneof![4 => 1..6usize, 1 => 0..FRAGMENTS.len()]
}

/// Mostly valid service types and endpoints, sometimes any.
fn service_value() -> impl Strategy<Value = (usize, usize)> {
    (
        prop_oneof![4 => 0..2usize, 1 => 0..SERVICE_TYPES.len()],
        prop_oneof![4 => 0..4usize, 1 => 0..ENDPOINTS.len()],
    )
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        20 => (fragment(), 0u8..5, 0..FLAGS.len(), key()).prop_map(|(fragment, method_type, flags, key)| Op::AddVm { fragment, method_type, flags, key }),
        8 => fragment().prop_map(|fragment| Op::RemoveVm { fragment }),
        12 => (fragment(), 0..FLAGS.len()).prop_map(|(fragment, flags)| Op::SetFlags { fragment, flags }),
        20 => (fragment(), service_value()).prop_map(|(fragment, (service_type, endpoint))| Op::AddService { fragment, service_type, endpoint }),
        20 => (fragment(), service_value()).prop_map(|(fragment, (service_type, endpoint))| Op::UpdateService { fragment, service_type, endpoint }),
        8 => fragment().prop_map(|fragment| Op::RemoveService { fragment }),
        8 => (proptest::collection::vec(0..SIGNERS + 2, 0..10), proptest::collection::vec(0..EXTERNALS.len(), 0..10)).prop_map(|(natives, externals)| Op::SetControllers { natives, externals }),
        1 => Just(Op::Deactivate),
    ]
}

/// A step on either DID. Its founding key signs most of the time, since a
/// stranger's update only ever exercises the authority checks.
fn step() -> impl Strategy<Value = Step> {
    (0..2usize)
        .prop_flat_map(|did| {
            (
                Just(did),
                prop_oneof![3 => Just(did), 1 => 0..SIGNERS],
                proptest::option::weighted(0.3, 0..2usize),
                op(),
            )
        })
        .prop_map(|(did, signer, via, op)| Step {
            did,
            signer,
            via,
            op,
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn random_updates_follow_the_model(steps in proptest::collection::vec(step(), 1..160)) {
        let mut world = World::new();
        for (n, step) in steps.iter().enumerate() {
            let method_type = match &step.op {
                Op::AddVm { method_type, .. } => *method_type,
                _ => 0,
            };
            let key = match &step.op {
                Op::AddVm { key, .. } => world.key(key, method_type),
                _ => Vec::new(),
            };
            let ix = instruction(&world, step, &key);
            let expected = if key_len(method_type).is_none() {
                Some(Outcome::Other("InstructionError(0, InvalidInstructionData)".into()))
            } else {
                world.model(step, &key).map(Outcome::Custom)
            };
            let got = world.send(step.signer, ix).err();
            prop_assert_eq!(got, expected, "step {} {:?}", n, step);

            for did in 0..2 {
                let address = Pubkey::new_from_array(client::did_account(&world.subjects[did]));
                let account = world.svm.get_account(&address).unwrap();
                let decoded = decode(&account.data);
                prop_assert_eq!(&decoded, &world.docs[did], "step {} DID {}", n, did);
                prop_assert_eq!(
                    account.lamports,
                    world.svm.minimum_balance_for_rent_exemption(account.data.len())
                );
            }
        }
    }
}
