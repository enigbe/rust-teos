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
fn signed_claim(
    txid: Txid,
    script: ScriptBuf,
    selector: &[u8],
    vout: u32,
    fee: u64,
) -> Transaction {
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100000 - fee),
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

pub fn to_local(delay: u16, vout: u32) -> Transaction {
    to_local_with_fee(commitment_txid(), delay, vout, 1000)
}

pub fn to_local_with_fee(txid: Txid, delay: u16, vout: u32, fee: u64) -> Transaction {
    signed_claim(
        txid,
        get_revokeable_redeemscript(
            &RevocationKey(public_key(1)),
            delay,
            &DelayedPaymentKey(public_key(2)),
        ),
        &[1],
        vout,
        fee,
    )
}

pub fn htlc(offered: bool, anchors: bool) -> Transaction {
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
        commitment_txid(),
        get_htlc_redeemscript(&output, &features, &keys),
        &public_key(1).serialize(),
        2,
        1000,
    )
}

pub fn justice(txs: Vec<Transaction>) -> JusticeTransactions {
    JusticeTransactions {
        revoked_commitment_txid: commitment_txid(),
        commitment_number: 42,
        txs,
    }
}
