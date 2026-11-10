use ldk_watchtower_client::{classify_claims, ClaimClassificationError, UnclassifiedClaimReason};
use lightning::bitcoin::absolute::LockTime;
use lightning::bitcoin::hashes::Hash;
use lightning::bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use lightning::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use lightning::bitcoin::transaction::Version;
use lightning::bitcoin::{
    ecdsa, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use lightning::chain::channelmonitor::JusticeTransactions;
use lightning::ln::chan_utils::{
    get_htlc_redeemscript, get_revokeable_redeemscript, HTLCOutputInCommitment, TxCreationKeys,
};
use lightning::ln::channel_keys::{DelayedPaymentKey, HtlcKey, RevocationKey};
use lightning::types::features::ChannelTypeFeatures;
use lightning::types::payment::PaymentHash;

fn public_key(value: u8) -> PublicKey {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[value; 32]).unwrap(),
    )
}

fn commitment_txid() -> Txid {
    Txid::from_byte_array([7; 32])
}

// Reproduce the pinned API's signed witness formats using LDK's script builders.
// These are classification fixtures, not an independent check of live monitor
// output. A real get_pending_justice_txs compatibility test belongs in the
// integration harness when the persistence adapter is introduced.
fn signed_claim(script: ScriptBuf, selector: &[u8], vout: u32) -> Transaction {
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: commitment_txid(),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(99000),
            script_pubkey: ScriptBuf::new_p2wpkh(&lightning::bitcoin::WPubkeyHash::hash(
                &public_key(6).serialize(),
            )),
        }],
    };
    let sighash = SighashCache::new(&transaction)
        .p2wsh_signature_hash(0, &script, Amount::from_sat(100000), EcdsaSighashType::All)
        .unwrap();
    let signature = Secp256k1::new().sign_ecdsa(
        &Message::from_digest(sighash.to_byte_array()),
        &SecretKey::from_slice(&[1; 32]).unwrap(),
    );
    transaction.input[0]
        .witness
        .push_ecdsa_signature(&ecdsa::Signature::sighash_all(signature));
    transaction.input[0].witness.push(selector);
    transaction.input[0].witness.push(script.as_bytes());
    transaction
}

fn to_local(delay: u16, vout: u32) -> Transaction {
    signed_claim(
        get_revokeable_redeemscript(
            &RevocationKey(public_key(1)),
            delay,
            &DelayedPaymentKey(public_key(2)),
        ),
        &[1],
        vout,
    )
}

fn htlc(offered: bool, anchors: bool) -> Transaction {
    let keys = TxCreationKeys {
        per_commitment_point: public_key(3),
        revocation_key: RevocationKey(public_key(1)),
        broadcaster_htlc_key: HtlcKey(public_key(4)),
        countersignatory_htlc_key: HtlcKey(public_key(5)),
        broadcaster_delayed_payment_key: DelayedPaymentKey(public_key(2)),
    };
    let output = HTLCOutputInCommitment {
        offered,
        amount_msat: 100000000,
        cltv_expiry: 500,
        payment_hash: PaymentHash([9; 32]),
        transaction_output_index: Some(2),
    };
    let features = if anchors {
        ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies()
    } else {
        ChannelTypeFeatures::only_static_remote_key()
    };
    signed_claim(
        get_htlc_redeemscript(&output, &features, &keys),
        &public_key(1).serialize(),
        2,
    )
}

fn justice(txs: Vec<Transaction>) -> JusticeTransactions {
    JusticeTransactions {
        revoked_commitment_txid: commitment_txid(),
        commitment_number: 42,
        txs,
    }
}

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
    fake_htlc[1] = public_key(1).serialize().to_vec();
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
