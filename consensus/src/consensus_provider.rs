// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::{
    counters,
    data_manager::{DataManager, DummyDataManager, QuorumStoreDataManager},
    epoch_manager::EpochManager,
    network::NetworkTask,
    network_interface::{ConsensusNetworkEvents, ConsensusNetworkSender},
    persistent_liveness_storage::StorageWriteProxy,
    state_computer::ExecutionProxy,
    txn_notifier::MempoolNotifier,
    util::time_service::ClockTimeService,
};
use aptos_config::config::NodeConfig;
use aptos_logger::prelude::*;
use aptos_mempool::QuorumStoreRequest;
use aptos_vm::AptosVM;
use consensus_notifications::ConsensusNotificationSender;
use event_notifications::ReconfigNotificationListener;
use executor::block_executor::BlockExecutor;
use futures::channel::mpsc;
use network::application::storage::PeerMetadataStorage;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use storage_interface::DbReaderWriter;
use tokio::runtime::{self, Runtime};

/// Helper function to start consensus based on configuration and return the runtime
pub fn start_consensus(
    node_config: &NodeConfig,
    mut network_sender: ConsensusNetworkSender,
    network_events: ConsensusNetworkEvents,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    consensus_to_mempool_tx: mpsc::Sender<QuorumStoreRequest>,
    aptos_db: DbReaderWriter,
    reconfig_events: ReconfigNotificationListener,
    peer_metadata_storage: Arc<PeerMetadataStorage>,
) -> Runtime {
    let runtime = runtime::Builder::new_multi_thread()
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("consensus-{}", id)
        })
        .disable_lifo_slot()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime!");
    let runtime_monitor = tokio_metrics::RuntimeMonitor::new(&runtime.handle());
    runtime.spawn(async move {
        for interval in runtime_monitor.intervals() {
            // pretty-print the metric interval
            // println!("ConsensusRuntime:{:?}", interval);
            // wait 500ms
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    let storage = Arc::new(StorageWriteProxy::new(node_config, aptos_db.reader.clone()));
    let txn_notifier = Arc::new(MempoolNotifier::new(
        consensus_to_mempool_tx.clone(),
        node_config.consensus.mempool_executed_txn_timeout_ms,
    ));

    let data_manager: Arc<dyn DataManager> = if node_config.consensus.use_quorum_store {
        Arc::new(QuorumStoreDataManager::new())
    } else {
        Arc::new(DummyDataManager::new())
    };

    let state_computer = Arc::new(ExecutionProxy::new(
        Arc::new(BlockExecutor::<AptosVM>::new(aptos_db)),
        txn_notifier,
        state_sync_notifier,
        data_manager.clone(),
        runtime.handle(),
    ));

    let time_service = Arc::new(ClockTimeService::new(runtime.handle().clone()));

    let (timeout_sender, timeout_receiver) = channel::new(1_024, &counters::PENDING_ROUND_TIMEOUTS);
    let (self_sender, self_receiver) = channel::new(1_024, &counters::PENDING_SELF_MESSAGES);
    network_sender.initialize(peer_metadata_storage);

    let epoch_mgr = EpochManager::new(
        node_config,
        time_service,
        self_sender,
        network_sender,
        timeout_sender,
        consensus_to_mempool_tx,
        state_computer,
        storage,
        reconfig_events,
        data_manager,
    );

    let (network_task, network_receiver) = NetworkTask::new(network_events, self_receiver);

    runtime.spawn(network_task.start());
    runtime.spawn(epoch_mgr.start(timeout_receiver, network_receiver));

    debug!("Consensus started.");
    runtime
}
