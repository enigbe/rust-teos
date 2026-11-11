use ldk_watchtower_client::{classify_claims, ClaimClassificationError, UnclassifiedClaimReason};
use lightning::bitcoin::hashes::Hash;
use lightning::bitcoin::sighash::EcdsaSighashType;
use lightning::bitcoin::{ScriptBuf, Txid, Witness};

mod common;
use common::{htlc, justice, to_local};

#[test]
fn selects_the_to_local_claim_and_its_delay() {
    let transaction = to_local(42, 5);
    let entry = justice(vec![transaction.clone()]);
    let classification = classify_claims(&entry).unwrap();
    let selected = classification.to_local().unwrap();

    assert_eq!(selected.transaction(), &transaction);
    assert_eq!(selected.to_self_delay(), 42);
    assert_eq!(classification.recognized_htlc_claims(), 0);
    assert!(classification.unclassified().is_empty());
}

#[test]
fn selects_to_local_regardless_of_claim_order() {
    let expected = to_local(144, 5);
    for position in 0..3 {
        let mut transactions = vec![expected.clone(), htlc(true, false), htlc(false, true)];
        transactions.rotate_left(position);
        let entry = justice(transactions);

        let classification = classify_claims(&entry).unwrap();
        assert_eq!(classification.to_local().unwrap().transaction(), &expected);
        assert_eq!(classification.recognized_htlc_claims(), 2);
        assert!(classification.unclassified().is_empty());
    }
}

#[test]
fn reports_an_empty_justice_entry() {
    let entry = justice(Vec::new());
    let classification = classify_claims(&entry).unwrap();
    assert!(classification.to_local().is_none());
    assert_eq!(classification.recognized_htlc_claims(), 0);
    assert!(classification.unclassified().is_empty());
}

#[test]
fn does_not_mistake_htlc_claims_for_an_omitted_to_local_claim() {
    for offered in [false, true] {
        for anchors in [false, true] {
            let entry = justice(vec![htlc(offered, anchors)]);
            let classification = classify_claims(&entry).unwrap();
            assert!(classification.to_local().is_none());
            assert_eq!(classification.recognized_htlc_claims(), 1);
            assert!(classification.unclassified().is_empty());
        }
    }
}

#[test]
fn rejects_multiple_to_local_candidates() {
    let mut unknown = htlc(true, false);
    unknown.input[0].witness = Witness::new();
    let entry = justice(vec![to_local(42, 0), unknown, to_local(42, 1)]);

    assert!(matches!(
        classify_claims(&entry),
        Err(ClaimClassificationError::AmbiguousToLocal)
    ));
}

#[test]
fn rejects_claims_for_another_commitment_even_after_a_match() {
    let mut other = htlc(true, false);
    other.input[0].previous_output.txid = Txid::from_byte_array([8; 32]);
    let entry = justice(vec![to_local(42, 5), other]);

    assert!(matches!(
        classify_claims(&entry),
        Err(ClaimClassificationError::UnexpectedCommitment)
    ));
}

#[test]
fn reports_unsupported_input_counts() {
    let mut missing = to_local(42, 5);
    missing.input.clear();
    let mut multiple = to_local(42, 5);
    multiple.input.push(multiple.input[0].clone());
    for transaction in [missing, multiple] {
        let entry = justice(vec![transaction]);
        let classification = classify_claims(&entry).unwrap();
        assert!(classification.to_local().is_none());
        assert_eq!(classification.recognized_htlc_claims(), 0);
        assert_eq!(classification.unclassified().len(), 1);
        assert_eq!(classification.unclassified()[0].transaction_index(), 0);
        assert_eq!(
            classification.unclassified()[0].reason(),
            UnclassifiedClaimReason::UnsupportedInputCount,
        );
    }
}

#[test]
fn reports_malformed_witnesses_and_delayed_spends() {
    let template = to_local(42, 5);
    let witness = template.input[0].witness.to_vec();
    let mut invalid_signature = witness.clone();
    invalid_signature[0] = vec![0];
    let mut delayed_spend = witness.clone();
    delayed_spend[1] = Vec::new();
    let mut fake_htlc = witness.clone();
    fake_htlc[1] = htlc(true, false).input[0].witness.to_vec()[1].clone();
    let mut malformed_script = witness.clone();
    malformed_script[2] = vec![0x63, 0x21];
    let mut trailing_opcode = witness.clone();
    trailing_opcode[2].push(0x61);
    // Signature format has its own diagnostic; the remaining cases are
    // unsupported witness shapes, selectors, or scripts.
    let witness_error = UnclassifiedClaimReason::UnsupportedWitness;
    for (stack, reason) in [
        (
            invalid_signature,
            UnclassifiedClaimReason::UnsupportedSignature,
        ),
        (Vec::new(), witness_error),
        (witness[..2].to_vec(), witness_error),
        (delayed_spend, witness_error),
        (fake_htlc, witness_error),
        (malformed_script, witness_error),
        (trailing_opcode, witness_error),
    ] {
        let mut transaction = template.clone();
        transaction.input[0].witness = Witness::from_slice(&stack);
        let entry = justice(vec![transaction]);
        let classification = classify_claims(&entry).unwrap();
        assert!(classification.to_local().is_none());
        assert_eq!(classification.unclassified().len(), 1);
        assert_eq!(classification.unclassified()[0].transaction_index(), 0);
        assert_eq!(classification.unclassified()[0].reason(), reason);
    }
}

#[test]
fn supports_ldk_delay_encodings_across_the_u16_range() {
    for delay in [0, 1, 16, 17, 127, 128, 255, 256, 32767, 32768, 65535] {
        let entry = justice(vec![to_local(delay, 5)]);
        assert_eq!(
            classify_claims(&entry)
                .unwrap()
                .to_local()
                .unwrap()
                .to_self_delay(),
            delay
        );
    }
}

#[test]
fn preserves_to_local_and_reports_unknown_claims_in_any_order() {
    let expected = to_local(144, 5);
    let mut signature_variant = htlc(true, true);
    let mut witness = signature_variant.input[0].witness.to_vec();
    *witness[0].last_mut().unwrap() = EcdsaSighashType::Single as u8;
    signature_variant.input[0].witness = Witness::from_slice(&witness);
    let mut multi_input = htlc(false, true);
    multi_input.input.push(multi_input.input[0].clone());

    for (unknown, reason) in [
        (
            signature_variant,
            UnclassifiedClaimReason::UnsupportedSignature,
        ),
        (multi_input, UnclassifiedClaimReason::UnsupportedInputCount),
    ] {
        for rotation in 0..3 {
            let mut transactions = vec![expected.clone(), htlc(true, false), unknown.clone()];
            transactions.rotate_left(rotation);
            let unknown_index = transactions.iter().position(|tx| tx == &unknown).unwrap();
            let entry = justice(transactions);
            let classification = classify_claims(&entry).unwrap();

            assert_eq!(classification.to_local().unwrap().transaction(), &expected);
            assert_eq!(classification.recognized_htlc_claims(), 1);
            assert_eq!(classification.unclassified().len(), 1);
            assert_eq!(
                classification.unclassified()[0].transaction_index(),
                unknown_index
            );
            assert_eq!(classification.unclassified()[0].reason(), reason);
        }
    }
}

#[test]
fn checks_commitment_binding_in_every_input_of_unknown_claims() {
    let mut unknown = htlc(true, true);
    let mut other_input = unknown.input[0].clone();
    other_input.previous_output.txid = Txid::from_byte_array([8; 32]);
    unknown.input.push(other_input);
    let entry = justice(vec![to_local(42, 5), unknown]);

    assert!(matches!(
        classify_claims(&entry),
        Err(ClaimClassificationError::UnexpectedCommitment)
    ));
}

#[test]
fn reports_nonempty_script_sigs_without_discarding_to_local() {
    let mut unknown = htlc(true, false);
    unknown.input[0].script_sig = ScriptBuf::from_bytes(vec![0]);
    let entry = justice(vec![unknown, to_local(42, 5)]);
    let classification = classify_claims(&entry).unwrap();

    assert!(classification.to_local().is_some());
    assert_eq!(classification.unclassified().len(), 1);
    assert_eq!(classification.unclassified()[0].transaction_index(), 0);
    assert_eq!(
        classification.unclassified()[0].reason(),
        UnclassifiedClaimReason::UnsupportedScriptSig
    );
}
