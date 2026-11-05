use ldk_watchtower_client::appointment_locator;
use lightning::chain::channelmonitor::JusticeTransactions;

#[test]
fn derives_locator_from_revoked_commitment_txid() {
    let justice = JusticeTransactions {
        revoked_commitment_txid: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            .parse()
            .unwrap(),
        commitment_number: 42,
        txs: Vec::new(),
    };

    // Locators use the first 16 bytes of the txid's internal representation,
    // which is reversed relative to the displayed transaction ID.
    assert_eq!(
        appointment_locator(&justice).as_ref(),
        &[
            0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12,
            0x11, 0x10,
        ]
    );
}
