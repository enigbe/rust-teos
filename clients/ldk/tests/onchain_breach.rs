//! Opt-in channel penalty tests against disposable regtest Bitcoin and TEOS.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ldk_watchtower_client::{
    classify_claims, ClientStore, CoverageOutcome, DeliveryCoordinator, LdkWatchtowerWorker,
    ProtectionScope, RetryPolicy, TowerClient, TowerConfig,
};
use lightning::bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use lightning::bitcoin::{Address, Block, Network, Transaction};
use lightning::chain::{BlockLocator, Watch};
use lightning::ln::channelmanager::{ChainParameters, ChannelManager};
use lightning::ln::functional_test_utils::{
    check_added_monitors, connect_block, create_chan_between_nodes_with_value_b,
    create_chanmon_cfgs, create_funding_transaction, create_network, create_node_cfgs,
    exchange_open_accept_chan, expect_channel_pending_event, expect_channel_ready_event,
    send_payment, test_default_channel_config, test_legacy_channel_config,
    update_nodes_with_chan_announce, Node,
};
use lightning::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use lightning::routing::gossip::NetworkGraph;
use lightning::sign::SignerProvider;
use lightning::util::test_utils::{
    TestBroadcaster, TestChainMonitor, TestChainSource, TestKeysInterface, TestMessageRouter,
    TestRouter,
};
use serde_json::{json, Value};
use teos_common::cryptography;

#[derive(Clone)]
struct Bitcoin {
    http: reqwest::Client,
    url: url::Url,
    user: String,
    password: String,
}

impl Bitcoin {
    fn from_env() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            url: std::env::var("TEOS_E2E_BITCOIN_RPC_URL")
                .expect("set TEOS_E2E_BITCOIN_RPC_URL to a disposable regtest Bitcoin RPC URL")
                .parse()
                .unwrap(),
            user: std::env::var("TEOS_E2E_BITCOIN_RPC_USER")
                .expect("set TEOS_E2E_BITCOIN_RPC_USER"),
            password: std::env::var("TEOS_E2E_BITCOIN_RPC_PASSWORD")
                .expect("set TEOS_E2E_BITCOIN_RPC_PASSWORD"),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Value {
        let response: Value = self
            .http
            .post(self.url.clone())
            .basic_auth(&self.user, Some(&self.password))
            .json(&json!({
                "jsonrpc": "1.0", "id": "ldk-breach-test",
                "method": method, "params": params,
            }))
            .send()
            .await
            .expect("Bitcoin RPC transport failed")
            .json()
            .await
            .expect("invalid Bitcoin RPC response");
        assert!(
            response["error"].is_null(),
            "{method}: {}",
            response["error"]
        );
        response
            .get("result")
            .expect("missing Bitcoin RPC result")
            .clone()
    }

    async fn block(&self, hash: &Value) -> Block {
        let raw = self.call("getblock", json!([hash, 0])).await;
        deserialize_hex(raw.as_str().unwrap()).unwrap()
    }

    async fn sync_nodes(&self, nodes: &[Node<'_, '_, '_>]) {
        let height = self
            .call("getblockcount", json!([]))
            .await
            .as_u64()
            .unwrap();
        for next in (nodes[0].best_block_info().1 as u64 + 1)..=height {
            let hash = self.call("getblockhash", json!([next])).await;
            let block = self.block(&hash).await;
            for node in nodes {
                connect_block(node, &block);
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable regtest Bitcoin and TEOS; mines blocks and creates a wallet"]
async fn live_teos_legacy_breach() {
    exercise_breach(false).await;
}

#[tokio::test]
#[ignore = "requires disposable regtest Bitcoin and TEOS; mines blocks and creates a wallet"]
async fn live_teos_anchor_breach() {
    exercise_breach(true).await;
}

async fn exercise_breach(anchors: bool) {
    let channel_config = if anchors {
        test_default_channel_config()
    } else {
        test_legacy_channel_config()
    };
    let bitcoin = Bitcoin::from_env();
    assert_eq!(
        bitcoin.call("getblockchaininfo", json!([])).await["chain"],
        "regtest",
        "the on-chain test is restricted to regtest"
    );
    let tower = TowerConfig::new(
        std::env::var("TEOS_E2E_TOWER_ID")
            .expect("set TEOS_E2E_TOWER_ID")
            .parse()
            .unwrap(),
        &std::env::var("TEOS_E2E_URL").expect("set TEOS_E2E_URL"),
        Duration::from_secs(10),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let wallet_name = format!(
        "ldk-breach-{}",
        directory.path().file_name().unwrap().to_str().unwrap()
    );
    bitcoin.call("createwallet", json!([wallet_name])).await;
    let wallet = Bitcoin {
        url: bitcoin.url.join(&format!("wallet/{wallet_name}")).unwrap(),
        ..bitcoin.clone()
    };
    let mining_address = wallet.call("getnewaddress", json!([])).await;
    bitcoin
        .call("generatetoaddress", json!([101, mining_address]))
        .await;

    // All LDK objects and both recording-only broadcasters leave scope before the
    // revoked commitment reaches Bitcoin. Neither node can publish a penalty.
    let (revoked, justice, sweep_script, delay) = {
        let mut chanmon_cfgs = create_chanmon_cfgs(2);
        for (index, cfg) in chanmon_cfgs.iter_mut().enumerate() {
            cfg.tx_broadcaster = TestBroadcaster::new(Network::Regtest);
            cfg.chain_source = TestChainSource::new(Network::Regtest);
            cfg.keys_manager = TestKeysInterface::new(&[index as u8; 32], Network::Regtest);
        }
        let victim = &chanmon_cfgs[1];
        let destination = victim.keys_manager.get_destination_script([0; 32]).unwrap();
        let mut worker = LdkWatchtowerWorker::new(
            ProtectionScope::ToLocalOnly,
            ClientStore::open(directory.path().join("client.sqlite")).unwrap(),
            vec![DeliveryCoordinator::new(
                TowerClient::new(tower.clone()).unwrap(),
                RetryPolicy::default(),
                RetryPolicy::default(),
            )],
            1000,
            destination.clone(),
        )
        .unwrap();
        TowerClient::new(tower.clone())
            .unwrap()
            .register(worker.store_mut())
            .await
            .unwrap();
        let adapter = worker.adapter();
        let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
        for (index, cfg) in node_cfgs.iter_mut().enumerate() {
            let base = &chanmon_cfgs[index];
            let graph = Arc::new(NetworkGraph::new(Network::Regtest, &base.logger));
            cfg.router = TestRouter::new(graph.clone(), &base.logger, &base.scorer);
            cfg.message_router = TestMessageRouter::new_default(graph.clone(), &base.keys_manager);
            cfg.network_graph = graph;
        }
        node_cfgs[1].chain_monitor = TestChainMonitor::new_with_watchtower(
            Some(&victim.chain_source),
            &victim.tx_broadcaster,
            &victim.logger,
            &victim.fee_estimator,
            &victim.persister,
            &victim.keys_manager,
            &adapter,
        );
        let managers = node_cfgs
            .iter()
            .map(|cfg| {
                ChannelManager::new(
                    cfg.fee_estimator,
                    &cfg.chain_monitor,
                    cfg.tx_broadcaster,
                    &cfg.router,
                    &cfg.message_router,
                    cfg.logger,
                    cfg.keys_manager,
                    cfg.keys_manager,
                    cfg.keys_manager,
                    channel_config.clone(),
                    ChainParameters {
                        network: Network::Regtest,
                        best_block: BlockLocator::from_network(Network::Regtest),
                    },
                    lightning::bitcoin::constants::genesis_block(Network::Regtest)
                        .header
                        .time,
                )
            })
            .collect();
        let nodes = create_network(2, &node_cfgs, &managers);
        bitcoin.sync_nodes(&nodes).await;
        let a = nodes[0].node.get_our_node_id();
        let b = nodes[1].node.get_our_node_id();
        let temporary = exchange_open_accept_chan(&nodes[0], &nodes[1], 1_000_000, 100_000_000);
        let (_, template, _) = create_funding_transaction(&nodes[0], &b, 1_000_000, 42);
        let funding_address =
            Address::from_script(&template.output[0].script_pubkey, Network::Regtest)
                .unwrap()
                .to_string();
        let outputs = serde_json::Map::from_iter([(funding_address, json!(0.01))]);
        // Let Bitcoin encode the unsigned zero-input template; rust-bitcoin uses
        // a witness encoding for empty inputs which Core's wallet cannot fund.
        let unsigned = wallet
            .call("createrawtransaction", json!([[], outputs]))
            .await;
        let funded = wallet
            .call(
                "fundrawtransaction",
                json!([unsigned, {"fee_rate": 2, "changePosition": 1}, false]),
            )
            .await;
        let signed = wallet
            .call("signrawtransactionwithwallet", json!([funded["hex"]]))
            .await;
        assert_eq!(signed["complete"], true);
        let funding: Transaction = deserialize_hex(signed["hex"].as_str().unwrap()).unwrap();
        assert_eq!(funding.output[0], template.output[0]);
        nodes[0]
            .node
            .funding_transaction_generated(temporary, b, funding.clone())
            .unwrap();
        let created = lightning::get_event_msg!(&nodes[0], MessageSendEvent::SendFundingCreated, b);
        nodes[1].node.handle_funding_created(a, &created);
        check_added_monitors(&nodes[1], 1);
        expect_channel_pending_event(&nodes[1], &a);
        let signed = lightning::get_event_msg!(&nodes[1], MessageSendEvent::SendFundingSigned, a);
        nodes[0].node.handle_funding_signed(b, &signed);
        check_added_monitors(&nodes[0], 1);
        expect_channel_pending_event(&nodes[0], &b);
        assert_eq!(
            nodes[0].tx_broadcaster.txn_broadcast(),
            vec![funding.clone()]
        );
        bitcoin
            .call("sendrawtransaction", json!([serialize_hex(&funding)]))
            .await;
        bitcoin
            .call("generatetoaddress", json!([6, mining_address]))
            .await;
        bitcoin.sync_nodes(&nodes).await;
        let ready_a = lightning::get_event_msg!(&nodes[0], MessageSendEvent::SendChannelReady, b);
        let ready_b = lightning::get_event_msg!(&nodes[1], MessageSendEvent::SendChannelReady, a);
        nodes[0].node.handle_channel_ready(b, &ready_b);
        let channel = ready_a.channel_id;
        let signatures_a =
            lightning::get_event_msg!(&nodes[0], MessageSendEvent::SendAnnouncementSignatures, b);
        expect_channel_ready_event(&nodes[0], &b);
        let (announcement, first_update, second_update) =
            create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &(ready_a, signatures_a));
        update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &first_update, &second_update);
        for node in &nodes {
            assert_eq!(
                node.node.list_channels()[0]
                    .channel_type
                    .as_ref()
                    .unwrap()
                    .supports_anchors_zero_fee_htlc_tx(),
                anchors,
                "both peers must negotiate the requested channel type"
            );
        }
        send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
        let revoked = nodes[0]
            .chain_monitor
            .chain_monitor
            .get_monitor(channel)
            .unwrap()
            .unsafe_get_latest_holder_commitment_txn(&nodes[0].logger)[0]
            .clone();
        send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
        let txid = revoked.compute_txid();
        let expected = {
            let monitor = nodes[1]
                .chain_monitor
                .chain_monitor
                .get_monitor(channel)
                .unwrap();
            let claims = monitor
                .get_pending_justice_txs(1000, destination.clone())
                .unwrap();
            let entry = claims
                .iter()
                .find(|entry| entry.revoked_commitment_txid == txid)
                .expect("the captured commitment must have been revoked");
            classify_claims(entry)
                .unwrap()
                .to_local()
                .expect("the revoked commitment must have a to_local claim")
                .transaction()
                .clone()
        };
        let (batches, _) = worker.poll(Instant::now()).into_parts();
        for (_, batch) in batches {
            let (recovery, attempts, _) = batch.into_parts();
            assert!(recovery.failures().is_empty());
            for attempt in attempts {
                worker.finish(attempt.send().await, Instant::now()).unwrap();
            }
        }
        let job = worker
            .store()
            .pending_appointment(channel, txid)
            .unwrap()
            .unwrap();
        let decrypted = cryptography::decrypt(&job.appointment().encrypted_blob, &txid).unwrap();
        // Separate LDK offers can sign the same claim with different nonces.
        // Check the transaction and revocation path here; below Bitcoin must
        // confirm the exact frozen payload, including its original signature.
        assert_eq!(decrypted.compute_txid(), expected.compute_txid());
        assert_eq!(
            decrypted.input[0]
                .witness
                .iter()
                .skip(1)
                .collect::<Vec<_>>(),
            expected.input[0].witness.iter().skip(1).collect::<Vec<_>>()
        );
        assert!(worker
            .store()
            .appointment_receipt(tower.tower_id(), channel, txid)
            .unwrap()
            .is_some());
        assert!(worker
            .store()
            .coverage_records(channel, txid)
            .unwrap()
            .iter()
            .any(|r| r.outcome() == CoverageOutcome::ToLocalAppointment && r.completion_ready()));
        nodes[1]
            .chain_monitor
            .chain_monitor
            .release_pending_monitor_events();
        assert!(
            !nodes[1]
                .chain_monitor
                .chain_monitor
                .get_monitor(channel)
                .unwrap()
                .pending_justice_commitment_txids()
                .contains(&txid),
            "normal ChainMonitor acknowledgment must release this commitment"
        );
        // Subscription state is observable after delivery, but remains separate
        // from the signed evidence already used for the acknowledgment above.
        let identity = worker.store_mut().load_or_create_identity().unwrap();
        let registration = worker
            .store()
            .registration(tower.tower_id(), identity.user_id())
            .unwrap()
            .unwrap();
        let info = TowerClient::new(tower.clone())
            .unwrap()
            .subscription_info(&identity)
            .await
            .unwrap();
        assert!(info.locators().contains(&job.appointment().locator));
        assert!(info.available_slots() < registration.available_slots());
        assert_eq!(
            info.subscription_expiry(),
            registration.subscription_expiry()
        );
        assert!(nodes.iter().all(|node| node
            .tx_broadcaster
            .txn_broadcasted
            .lock()
            .unwrap()
            .is_empty()));
        (
            revoked,
            decrypted,
            destination,
            job.appointment().to_self_delay,
        )
    };

    let anchor_outputs = revoked
        .output
        .iter()
        .filter(|output| output.value.to_sat() == 330 && output.script_pubkey.is_p2wsh())
        .count();
    assert_eq!(
        anchor_outputs,
        if anchors { 2 } else { 0 },
        "the published commitment must have the expected 330-sat P2WSH anchor outputs"
    );
    assert_eq!(justice.input.len(), 1);
    assert_eq!(justice.output.len(), 1);
    assert_eq!(
        justice.input[0].previous_output.txid,
        revoked.compute_txid()
    );
    assert_eq!(justice.output[0].script_pubkey, sweep_script);
    let breached_output = &revoked.output[justice.input[0].previous_output.vout as usize];
    assert!(breached_output.value > justice.output[0].value);
    let accept = bitcoin
        .call("testmempoolaccept", json!([[serialize_hex(&revoked)]]))
        .await;
    assert_eq!(
        accept[0]["allowed"], true,
        "revoked commitment must be valid on regtest: {accept}"
    );
    bitcoin
        .call("sendrawtransaction", json!([serialize_hex(&revoked)]))
        .await;
    let breach_blocks = bitcoin
        .call("generatetoaddress", json!([1, mining_address]))
        .await;
    let breach_height = bitcoin
        .call("getblockcount", json!([]))
        .await
        .as_u64()
        .unwrap();
    assert!(bitcoin
        .block(&breach_blocks[0])
        .await
        .txdata
        .iter()
        .any(|tx| tx.compute_txid() == revoked.compute_txid()));
    let justice_txid = justice.compute_txid().to_string();
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let mempool = bitcoin.call("getrawmempool", json!([])).await;
            if mempool
                .as_array()
                .unwrap()
                .iter()
                .any(|txid| txid.as_str() == Some(&justice_txid))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("TEOS did not broadcast the saved justice transaction after the breach");
    let mined = bitcoin
        .call("generatetoaddress", json!([1, mining_address]))
        .await;
    let block = bitcoin.block(&mined[0]).await;
    assert!(
        block.txdata.contains(&justice),
        "the exact LDK justice transaction must confirm"
    );
    let height = bitcoin
        .call("getblockcount", json!([]))
        .await
        .as_u64()
        .unwrap();
    assert!(
        height < breach_height + u64::from(delay),
        "justice must confirm before the delayed spend matures"
    );
    let recovered = bitcoin.call("gettxout", json!([justice_txid, 0])).await;
    assert_eq!(recovered["confirmations"], 1);
    assert_eq!(
        recovered["scriptPubKey"]["address"],
        Address::from_script(&sweep_script, Network::Regtest)
            .unwrap()
            .to_string()
    );
    let spent = justice.input[0].previous_output;
    assert!(
        bitcoin
            .call("gettxout", json!([spent.txid.to_string(), spent.vout]))
            .await
            .is_null(),
        "the breached output must be spent after the exact justice transaction confirms"
    );
    bitcoin.call("unloadwallet", json!([wallet_name])).await;
}
