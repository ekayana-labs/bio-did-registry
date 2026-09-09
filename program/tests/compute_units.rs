//! Compute unit report: replays one full DID lifecycle and prints the CU
//! consumed per instruction, asserting a generous ceiling per instruction so
//! CI catches cost regressions.
//!
//! Run with output: `cargo test --test compute_units -- --nocapture`

use std::path::PathBuf;
use std::str::FromStr;

use litesvm::LiteSVM;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

const PROGRAM_ID: &str = "H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6";

/// Per-instruction ceiling. Measured costs sit at 3-8k CU; a breach of this
/// bound means something regressed badly.
const CU_CEILING: u64 = 15_000;

/// Largest chunk that keeps a single-signer `write_key_buffer` transaction
/// under the 1232 byte packet limit.
const CHUNK: usize = 900;

fn program_id() -> Pubkey {
    Pubkey::from_str(PROGRAM_ID).unwrap()
}

fn system_program() -> Pubkey {
    Pubkey::from_str("11111111111111111111111111111111").unwrap()
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

struct World {
    svm: LiteSVM,
    subject: Keypair,
    pda: Pubkey,
    key_buffer: Pubkey,
}

impl World {
    fn new() -> Self {
        let so = std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/bio_did_registry.so"),
        )
        .expect("build first: cargo build-sbf --manifest-path program/Cargo.toml");
        let mut svm = LiteSVM::new();
        svm.add_program(program_id(), &so).unwrap();
        let subject = Keypair::new();
        svm.airdrop(&subject.pubkey(), 10_000_000_000).unwrap();
        let pda =
            Pubkey::find_program_address(&[b"bio-did", subject.pubkey().as_ref()], &program_id()).0;
        let key_buffer = Pubkey::find_program_address(
            &[b"bio-did-key", pda.as_ref(), subject.pubkey().as_ref()],
            &program_id(),
        )
        .0;
        World {
            svm,
            subject,
            pda,
            key_buffer,
        }
    }

    fn send_accounts(&mut self, data: Vec<u8>, accounts: Vec<AccountMeta>) -> u64 {
        let ix = Instruction {
            program_id: program_id(),
            accounts,
            data,
        };
        let blockhash = self.svm.latest_blockhash();
        let msg = Message::new_with_blockhash(&[ix], Some(&self.subject.pubkey()), &blockhash);
        let tx =
            VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[&self.subject]).unwrap();
        let meta = self
            .svm
            .send_transaction(tx)
            .unwrap_or_else(|e| panic!("tx failed: {:?} logs: {:?}", e.err, e.meta.logs));
        meta.compute_units_consumed
    }

    /// [payer, authority, did_account, system_program] or [authority, did_account].
    fn send(&mut self, data: Vec<u8>, with_realloc_metas: bool) -> u64 {
        let s = self.subject.pubkey();
        let accounts = if with_realloc_metas {
            vec![
                AccountMeta::new(s, true),
                AccountMeta::new_readonly(s, true),
                AccountMeta::new(self.pda, false),
                AccountMeta::new_readonly(system_program(), false),
            ]
        } else {
            vec![
                AccountMeta::new_readonly(s, true),
                AccountMeta::new(self.pda, false),
            ]
        };
        self.send_accounts(data, accounts)
    }

    /// [payer, authority, did_account, key_buffer, system_program].
    fn send_buffer(&mut self, data: Vec<u8>) -> u64 {
        let s = self.subject.pubkey();
        let accounts = vec![
            AccountMeta::new(s, true),
            AccountMeta::new_readonly(s, true),
            AccountMeta::new(self.pda, false),
            AccountMeta::new(self.key_buffer, false),
            AccountMeta::new_readonly(system_program(), false),
        ];
        self.send_accounts(data, accounts)
    }

    fn send_initialize(&mut self) -> u64 {
        let s = self.subject.pubkey();
        let mut data = [175u8, 175, 109, 31, 13, 152, 155, 237].to_vec();
        data.extend_from_slice(s.as_ref());
        let accounts = vec![
            AccountMeta::new(s, true),
            AccountMeta::new(self.pda, false),
            AccountMeta::new_readonly(system_program(), false),
        ];
        self.send_accounts(data, accounts)
    }

    fn create_key_buffer(&mut self, fragment: &str) -> u64 {
        let mut data = [138u8, 70, 101, 189, 154, 98, 203, 23].to_vec();
        put_str(&mut data, fragment);
        data.push(3); // MlDsa87
        data.extend_from_slice(&(1u16 << 1).to_le_bytes());
        data.extend_from_slice(&2592u32.to_le_bytes());
        self.send_buffer(data)
    }

    fn write_key_buffer(&mut self, offset: usize, chunk: &[u8]) -> u64 {
        let s = self.subject.pubkey();
        let mut data = [61u8, 88, 82, 10, 227, 249, 18, 117].to_vec();
        data.extend_from_slice(&(offset as u32).to_le_bytes());
        data.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        data.extend_from_slice(chunk);
        let accounts = vec![
            AccountMeta::new_readonly(s, true),
            AccountMeta::new(self.key_buffer, false),
        ];
        self.send_accounts(data, accounts)
    }
}

#[test]
fn lifecycle_compute_unit_report() {
    let rotation = Keypair::new();
    let lab = Keypair::new().pubkey();
    let lab2 = Keypair::new().pubkey();
    let mut w = World::new();

    type Step<'a> = (&'a str, Box<dyn Fn(&mut World) -> u64>);
    let steps: Vec<Step> = vec![
        ("initialize", Box::new(|w: &mut World| w.send_initialize())),
        (
            "add_verification_method (Ed25519)",
            Box::new(move |w: &mut World| {
                let mut data = [213u8, 200, 190, 61, 28, 104, 245, 25].to_vec();
                put_str(&mut data, "rotation-1");
                data.push(0); // Ed25519
                data.extend_from_slice(&(1u16 | 1 << 3).to_le_bytes());
                data.extend_from_slice(&32u32.to_le_bytes());
                data.extend_from_slice(rotation.pubkey().as_ref());
                w.send(data, true)
            }),
        ),
        (
            "create_key_buffer (ML-DSA-87, 2592 B)",
            Box::new(|w: &mut World| w.create_key_buffer("pq-1")),
        ),
        (
            "write_key_buffer (chunk 1/3, 900 B)",
            Box::new(|w: &mut World| w.write_key_buffer(0, &[7u8; CHUNK])),
        ),
        (
            "write_key_buffer (chunk 2/3, 900 B)",
            Box::new(|w: &mut World| w.write_key_buffer(CHUNK, &[7u8; CHUNK])),
        ),
        (
            "write_key_buffer (chunk 3/3, 792 B)",
            Box::new(|w: &mut World| w.write_key_buffer(2 * CHUNK, &[7u8; 2592 - 2 * CHUNK])),
        ),
        (
            "add_verification_method_from_buffer (2592 B)",
            Box::new(|w: &mut World| {
                w.send_buffer([111u8, 184, 129, 9, 216, 207, 122, 90].to_vec())
            }),
        ),
        (
            "set_verification_method_flags",
            Box::new(|w: &mut World| {
                let mut data = [16u8, 188, 26, 223, 241, 131, 192, 223].to_vec();
                put_str(&mut data, "rotation-1");
                data.extend_from_slice(&(1u16 | 1 << 1 | 1 << 3).to_le_bytes());
                w.send(data, false)
            }),
        ),
        (
            "add_service",
            Box::new(|w: &mut World| {
                let mut data = [133u8, 207, 106, 32, 91, 111, 153, 30].to_vec();
                put_str(&mut data, "metadata");
                put_str(&mut data, "BioMetadata");
                put_str(
                    &mut data,
                    "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                );
                w.send(data, true)
            }),
        ),
        (
            "set_controllers (2 native + 2 other)",
            Box::new(move |w: &mut World| {
                let mut data = [65u8, 40, 24, 8, 30, 81, 20, 179].to_vec();
                data.extend_from_slice(&2u32.to_le_bytes());
                data.extend_from_slice(lab.as_ref());
                data.extend_from_slice(lab2.as_ref());
                data.extend_from_slice(&2u32.to_le_bytes());
                put_str(&mut data, "did:web:lab.example.org");
                put_str(
                    &mut data,
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                );
                w.send(data, true)
            }),
        ),
        (
            "remove_service",
            Box::new(|w: &mut World| {
                let mut data = [19u8, 102, 8, 231, 40, 141, 9, 110].to_vec();
                put_str(&mut data, "metadata");
                w.send(data, true)
            }),
        ),
        (
            "remove_verification_method (2592 B)",
            Box::new(|w: &mut World| {
                let mut data = [33u8, 238, 66, 183, 62, 210, 133, 150].to_vec();
                put_str(&mut data, "pq-1");
                w.send(data, true)
            }),
        ),
        (
            "create_key_buffer (abandoned)",
            Box::new(|w: &mut World| w.create_key_buffer("pq-2")),
        ),
        (
            "close_key_buffer",
            Box::new(|w: &mut World| {
                let s = w.subject.pubkey();
                let accounts = vec![
                    AccountMeta::new(s, true),
                    AccountMeta::new_readonly(s, true),
                    AccountMeta::new(w.key_buffer, false),
                ];
                w.send_accounts([6u8, 209, 103, 32, 78, 18, 70, 184].to_vec(), accounts)
            }),
        ),
        (
            "deactivate",
            Box::new(|w: &mut World| w.send([44u8, 112, 33, 172, 113, 28, 142, 13].to_vec(), true)),
        ),
    ];

    println!();
    println!("{:<46} {:>10}", "instruction", "CU");
    println!("{}", "-".repeat(58));
    let mut total = 0u64;
    let count = steps.len();
    for (name, run) in steps {
        let cu = run(&mut w);
        total += cu;
        println!("{name:<46} {cu:>10}");
        assert!(
            cu < CU_CEILING,
            "`{name}` consumed {cu} CU (ceiling {CU_CEILING})"
        );
    }
    println!("{}", "-".repeat(58));
    println!(
        "{:<46} {total:>10}",
        format!("TOTAL ({count} instructions)")
    );
}
