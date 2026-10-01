//! Property tests for the account layout code in `state` and `reader`.
//!
//! Random documents are encoded by a writer in this file, which follows the
//! documented layout and shares no code with the crate, then read back
//! through the crate's parser and views. Arbitrary bytes must never panic.

use bio_did_registry::{
    error::DidError,
    reader::{Account, Reader},
    state::*,
};
use pinocchio::error::ProgramError;
use proptest::prelude::*;

#[derive(Clone, Debug)]
struct Vm {
    fragment: Vec<u8>,
    method_type: u8,
    flags: u16,
    key: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Svc {
    fragment: Vec<u8>,
    service_type: Vec<u8>,
    endpoint: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Doc {
    deactivated: bool,
    natives: Vec<[u8; 32]>,
    others: Vec<Vec<u8>>,
    vms: Vec<Vm>,
    services: Vec<Svc>,
}

/// Where the writer put each entry: `(start, flags_pos, end)` for methods
/// and `(start, end)` for services.
struct Spans {
    vms: Vec<(usize, usize, usize)>,
    services: Vec<(usize, usize)>,
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn encode(doc: &Doc) -> (Vec<u8>, Spans) {
    let mut out = ACCOUNT_DISCRIMINATOR.to_vec();
    out.extend_from_slice(&5u64.to_le_bytes());
    out.push(253);
    out.extend_from_slice(&[4u8; 32]);
    out.push(doc.deactivated as u8);
    out.extend_from_slice(&1_700_000_000i64.to_le_bytes());
    out.extend_from_slice(&(doc.natives.len() as u32).to_le_bytes());
    for key in &doc.natives {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&(doc.others.len() as u32).to_le_bytes());
    for other in &doc.others {
        put(&mut out, other);
    }
    let mut spans = Spans {
        vms: Vec::new(),
        services: Vec::new(),
    };
    out.extend_from_slice(&(doc.vms.len() as u32).to_le_bytes());
    for vm in &doc.vms {
        let start = out.len();
        put(&mut out, &vm.fragment);
        out.push(vm.method_type);
        let flags_pos = out.len();
        out.extend_from_slice(&vm.flags.to_le_bytes());
        put(&mut out, &vm.key);
        spans.vms.push((start, flags_pos, out.len()));
    }
    out.extend_from_slice(&(doc.services.len() as u32).to_le_bytes());
    for svc in &doc.services {
        let start = out.len();
        put(&mut out, &svc.fragment);
        put(&mut out, &svc.service_type);
        put(&mut out, &svc.endpoint);
        spans.services.push((start, out.len()));
    }
    (out, spans)
}

fn fragment() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        prop_oneof![
            b'a'..=b'z',
            b'A'..=b'Z',
            b'0'..=b'9',
            Just(b'_'),
            Just(b'-')
        ],
        1..=MAX_FRAGMENT_LEN,
    )
}

fn printable(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(0x21u8..=0x7e, 1..=max)
}

/// Strings near the external controller form, valid and not.
fn controller_like() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![Just("did:"), Just("DID:"), Just("did"), Just("")],
        prop_oneof![
            Just("web".to_string()),
            Just("bio".to_string()),
            "[a-z0-9]{0,6}",
            "[A-Za-z]{1,4}"
        ],
        prop_oneof![Just(":"), Just(""), Just("::")],
        printable(130),
    )
        .prop_map(|(scheme, method, colon, id)| {
            let mut value = format!("{scheme}{method}{colon}").into_bytes();
            value.extend_from_slice(&id);
            value
        })
}

fn vm() -> impl Strategy<Value = Vm> {
    (fragment(), 0u8..4, any::<u16>(), any::<u8>()).prop_map(
        |(fragment, method_type, flags, fill)| Vm {
            fragment,
            method_type,
            flags,
            key: vec![fill; expected_key_len(method_type).unwrap()],
        },
    )
}

fn svc() -> impl Strategy<Value = Svc> {
    (
        fragment(),
        printable(MAX_SERVICE_TYPE_LEN),
        printable(MAX_ENDPOINT_LEN),
    )
        .prop_map(|(fragment, service_type, endpoint)| Svc {
            fragment,
            service_type,
            endpoint,
        })
}

/// A document within every limit, with fragments unique across methods and
/// services, as the program keeps them.
fn doc() -> impl Strategy<Value = Doc> {
    (
        any::<bool>(),
        proptest::collection::vec(any::<[u8; 32]>(), 0..=MAX_NATIVE_CONTROLLERS),
        proptest::collection::vec(printable(MAX_CONTROLLER_LEN), 0..=MAX_OTHER_CONTROLLERS),
        proptest::collection::vec(vm(), 0..=MAX_VERIFICATION_METHODS),
        proptest::collection::vec(svc(), 0..=MAX_SERVICES),
    )
        .prop_map(|(deactivated, natives, others, mut vms, mut services)| {
            let mut seen = std::collections::HashSet::new();
            vms.retain(|vm| seen.insert(vm.fragment.clone()));
            services.retain(|svc| seen.insert(svc.fragment.clone()));
            Doc {
                deactivated,
                natives,
                others,
                vms,
                services,
            }
        })
}

proptest! {
    #[test]
    fn parsers_never_panic_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(doc) = DidView::parse(&data) {
            let s = doc.sections();
            prop_assert_eq!(s.end, data.len());
            prop_assert_eq!(doc.vms().count(), s.vm_count);
            prop_assert_eq!(doc.services().count(), s.svc_count);
        }
        let _ = Sections::parse(&data);
        let _ = KeyBufferRef::parse(&data);
    }

    #[test]
    fn documents_read_back_with_their_spans(model in doc()) {
        let (data, spans) = encode(&model);
        let view = DidView::parse(&data).unwrap();
        let s = view.sections();
        prop_assert_eq!(s.end, data.len());
        prop_assert_eq!(view.is_deactivated(), model.deactivated);
        prop_assert_eq!(s.nc_count, model.natives.len());
        prop_assert_eq!(s.oc_count, model.others.len());

        let vms: Vec<VmRef> = view.vms().collect();
        prop_assert_eq!(vms.len(), model.vms.len());
        for ((vm, want), (start, flags_pos, end)) in vms.iter().zip(&model.vms).zip(&spans.vms) {
            prop_assert_eq!(vm.fragment, &want.fragment[..]);
            prop_assert_eq!(vm.method_type, want.method_type);
            prop_assert_eq!(vm.flags, want.flags);
            prop_assert_eq!(vm.key, &want.key[..]);
            prop_assert_eq!((vm.start, vm.flags_pos, vm.end), (*start, *flags_pos, *end));
            prop_assert_eq!(view.find_vm(&want.fragment).map(|found| found.start), Some(*start));
        }
        let svcs: Vec<SvcRef> = view.services().collect();
        prop_assert_eq!(svcs.len(), model.services.len());
        for ((svc, want), (start, end)) in svcs.iter().zip(&model.services).zip(&spans.services) {
            prop_assert_eq!(svc.fragment, &want.fragment[..]);
            prop_assert_eq!((svc.start, svc.end), (*start, *end));
            prop_assert_eq!(view.find_service(&want.fragment).map(|found| found.start), Some(*start));
        }

        for key in &model.natives {
            prop_assert!(view.is_native_controller(key));
        }
        prop_assert!(!view.is_native_controller(&[0xee; 32]) || model.natives.contains(&[0xee; 32]));

        let authorities: Vec<&Vm> = model
            .vms
            .iter()
            .filter(|vm| vm.method_type == VM_TYPE_ED25519 && vm.flags & VM_FLAG_CAPABILITY_INVOCATION != 0)
            .collect();
        prop_assert_eq!(view.authority_count(), authorities.len());
        for vm in &authorities {
            let key: [u8; 32] = vm.key[..].try_into().unwrap();
            prop_assert!(view.is_authority(&key));
            let expected = if model.deactivated {
                Err(ProgramError::from(DidError::DidDeactivated))
            } else {
                Ok(())
            };
            prop_assert_eq!(view.require_authority(&key), expected);
        }
    }

    #[test]
    fn a_document_with_bytes_missing_or_extra_is_refused(model in doc(), cut in 1usize..64, extra in proptest::collection::vec(any::<u8>(), 1..16)) {
        let (data, _) = encode(&model);
        let short = &data[..data.len().saturating_sub(cut)];
        prop_assert!(DidView::parse(short).is_err());
        let mut long = data.clone();
        long.extend_from_slice(&extra);
        prop_assert!(DidView::parse(&long).is_err());
    }

    #[test]
    fn inserted_methods_and_rewritten_services_read_back(
        model in doc(),
        new in vm(),
        endpoint in printable(MAX_ENDPOINT_LEN),
    ) {
        prop_assume!(model.vms.len() < MAX_VERIFICATION_METHODS);
        prop_assume!(!model.vms.iter().any(|vm| vm.fragment == new.fragment));
        prop_assume!(!model.services.iter().any(|svc| svc.fragment == new.fragment));
        let (mut data, _) = encode(&model);
        let s = *DidView::parse(&data).unwrap().sections();
        data.resize(s.end + vm_space(new.fragment.len(), new.key.len()), 0);
        let method = NewMethod {
            fragment: &new.fragment,
            method_type: new.method_type,
            flags: new.flags,
            key_len: new.key.len(),
        };
        insert_vm(&mut data, &s, &method, &new.key);

        let mut expected = model.clone();
        expected.vms.push(new.clone());
        prop_assert_eq!(&data, &encode(&expected).0);

        // A service rewritten in place with a new endpoint of another size.
        if let Some(first) = model.services.first() {
            let view = DidView::parse(&data).unwrap();
            let svc = view.find_service(&first.fragment).unwrap();
            let (start, end, old_len) = (svc.start, svc.end, view.sections().end);
            let entry_end = start + service_space(first.fragment.len(), first.service_type.len(), endpoint.len());
            let new_len = old_len - end + entry_end;
            if new_len > old_len {
                data.resize(new_len, 0);
            }
            data.copy_within(end..old_len, entry_end);
            write_service(&mut data, start, &first.fragment, &first.service_type, &endpoint);
            data.truncate(new_len);
            expected.services[0].endpoint = endpoint.clone();
            prop_assert_eq!(&data, &encode(&expected).0);
        }
    }

    #[test]
    fn key_buffer_headers_read_back(
        did_account in any::<[u8; 32]>(),
        authority in any::<[u8; 32]>(),
        bump in any::<u8>(),
        method_type in any::<u8>(),
        flags in any::<u16>(),
        key_len in 0usize..3000,
        written in 0usize..3000,
        fragment in fragment(),
    ) {
        let mut data = KEY_BUFFER_DISCRIMINATOR.to_vec();
        data.extend_from_slice(&did_account);
        data.extend_from_slice(&authority);
        data.push(bump);
        data.push(method_type);
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&(key_len as u32).to_le_bytes());
        data.extend_from_slice(&(written as u32).to_le_bytes());
        data.extend_from_slice(&(fragment.len() as u32).to_le_bytes());
        let mut padded = fragment.clone();
        padded.resize(MAX_FRAGMENT_LEN, 0);
        data.extend_from_slice(&padded);
        prop_assert_eq!(data.len(), KEY_BUFFER_HEADER);
        data.resize(KEY_BUFFER_HEADER + key_len, 7);

        match KeyBufferRef::parse(&data) {
            Ok(kb) => {
                prop_assert!(written <= key_len);
                prop_assert_eq!(kb.did_account, &did_account[..]);
                prop_assert_eq!(kb.authority, &authority[..]);
                prop_assert_eq!((kb.bump, kb.method_type, kb.flags), (bump, method_type, flags));
                prop_assert_eq!((kb.key_len, kb.written), (key_len, written));
                prop_assert_eq!(kb.fragment, &fragment[..]);
                prop_assert_eq!(kb.key(&data).len(), written);
            }
            Err(_) => prop_assert!(written > key_len),
        }
        data.push(0);
        prop_assert!(KeyBufferRef::parse(&data).is_err());
    }

    #[test]
    fn reader_consumes_exactly_what_it_returns(
        data in proptest::collection::vec(any::<u8>(), 0..64),
        reads in proptest::collection::vec(0usize..12, 0..12),
    ) {
        let mut r = Reader::<Account>::new(&data);
        let mut at = 0usize;
        for n in reads {
            match r.bytes(n) {
                Ok(bytes) => {
                    prop_assert_eq!(bytes, &data[at..at + n]);
                    at += n;
                }
                Err(e) => {
                    prop_assert!(at + n > data.len());
                    prop_assert_eq!(e, ProgramError::InvalidAccountData);
                }
            }
            prop_assert_eq!(r.offset(), at);
            prop_assert_eq!(r.remaining(), &data[at..]);
        }
        prop_assert_eq!(r.finish().is_ok(), at == data.len());
    }

    #[test]
    fn validators_match_their_definitions(value in prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..140),
        fragment(),
        controller_like(),
    ]) {
        let fragment_ok = (1..=32).contains(&value.len())
            && value.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-');
        prop_assert_eq!(valid_fragment(&value), fragment_ok);

        let printable_ok = |max: usize| {
            !value.is_empty() && value.len() <= max && value.iter().all(|b| b.is_ascii_graphic())
        };
        prop_assert_eq!(valid_uri_ascii(&value, 64), printable_ok(64));

        let text = String::from_utf8_lossy(&value);
        let controller_ok = printable_ok(128)
            && text.strip_prefix("did:").is_some_and(|rest| match rest.split_once(':') {
                Some((method, id)) => {
                    !method.is_empty()
                        && method != "bio"
                        && method.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                        && !id.is_empty()
                }
                None => false,
            });
        prop_assert_eq!(valid_external_controller(&value), controller_ok);
    }
}

/// Every flag value on every type tag, against the rules as the spec lists
/// them. Exhaustive, since there are only 5 * 65536 cases.
#[test]
fn flag_rules_hold_for_every_value() {
    for method_type in 0u8..5 {
        for flags in 0..=u16::MAX {
            let known = flags & !VM_VALID_MASK == 0;
            let signs = flags & (VM_FLAG_CAPABILITY_INVOCATION | VM_FLAG_PROTECTED) == 0
                || method_type == VM_TYPE_ED25519;
            let protected_holds_authority =
                flags & VM_FLAG_PROTECTED == 0 || flags & VM_FLAG_CAPABILITY_INVOCATION != 0;
            let x25519_agrees_only = method_type != VM_TYPE_X25519
                || flags & VM_RELATIONSHIP_MASK & !VM_FLAG_KEY_AGREEMENT == 0;
            let ml_dsa_signs_only =
                method_type != VM_TYPE_DILITHIUM5 || flags & VM_FLAG_KEY_AGREEMENT == 0;
            let allowed = known
                && signs
                && protected_holds_authority
                && x25519_agrees_only
                && ml_dsa_signs_only;
            let got = validate_vm_flags(method_type, flags);
            assert_eq!(
                got.is_ok(),
                allowed,
                "type {method_type} flags {flags:#06x}: {got:?}"
            );
            if !allowed {
                assert_eq!(got, Err(DidError::InvalidFlags.into()));
            }
        }
    }
}
