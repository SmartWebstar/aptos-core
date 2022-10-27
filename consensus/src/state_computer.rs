// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::{
    block_storage::tracing::{observe_block, BlockStage},
    counters,
    data_manager::DataManager,
    error::StateSyncError,
    monitor,
    state_replication::{StateComputer, StateComputerCommitCallBackType},
    txn_notifier::TxnNotifier,
};
use anyhow::Result;
use aptos_crypto::HashValue;
use aptos_infallible::Mutex;
use aptos_logger::prelude::*;
use aptos_types::{
    account_address::AccountAddress,
    contract_event::ContractEvent,
    epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures,
    transaction::{ExecutionStatus, Transaction, TransactionStatus},
};
use consensus_notifications::ConsensusNotificationSender;
use consensus_types::{
    block::Block,
    common::{Payload, Round},
    executed_block::ExecutedBlock,
    proof_of_store::LogicalTime,
};
use executor_types::{BlockExecutorTrait, Error as ExecutionError, StateComputeResult};
use fail::fail_point;
use futures::{SinkExt, StreamExt};
use std::{boxed::Box, cmp::max, sync::Arc};
use tokio::sync::Mutex as AsyncMutex;

type NotificationType = (
    Box<dyn FnOnce() + Send + Sync>,
    Vec<Transaction>,
    Vec<ContractEvent>,
);

type CommitType = (u64, Round, Vec<Payload>);

/// Basic communication with the Execution module;
/// implements StateComputer traits.
pub struct ExecutionProxy {
    executor: Arc<dyn BlockExecutorTrait>,
    txn_notifier: Arc<dyn TxnNotifier>,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    async_state_sync_notifier: channel::Sender<NotificationType>,
    async_commit_notifier: channel::Sender<CommitType>,
    validators: Mutex<Vec<AccountAddress>>,
    write_mutex: AsyncMutex<()>,
    data_manager: Arc<dyn DataManager>,
}

impl ExecutionProxy {
    pub fn new(
        executor: Arc<dyn BlockExecutorTrait>,
        txn_notifier: Arc<dyn TxnNotifier>,
        state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
        data_manager: Arc<dyn DataManager>,
        handle: &tokio::runtime::Handle,
    ) -> Self {
        let (tx, mut rx) =
            channel::new::<NotificationType>(10, &counters::PENDING_STATE_SYNC_NOTIFICATION);
        let notifier = state_sync_notifier.clone();
        handle.spawn(async move {
            while let Some((callback, txns, reconfig_events)) = rx.next().await {
                if let Err(e) = monitor!(
                    "notify_state_sync",
                    notifier.notify_new_commit(txns, reconfig_events).await
                ) {
                    error!(error = ?e, "Failed to notify state synchronizer");
                }

                callback();
            }
        });
        let (commit_tx, mut commit_rx) =
            channel::new::<CommitType>(10, &counters::PENDING_QUORUM_STORE_COMMIT_NOTIFICATION);
        let data_manager_clone = data_manager.clone();
        handle.spawn(async move {
            while let Some((epoch, round, payloads)) = commit_rx.next().await {
                debug!("notifying commit for round: {}", round);
                data_manager_clone
                    .notify_commit(LogicalTime::new(epoch, round), payloads)
                    .await;
            }
        });
        Self {
            executor,
            txn_notifier,
            state_sync_notifier,
            async_state_sync_notifier: tx,
            async_commit_notifier: commit_tx,
            validators: Mutex::new(vec![]),
            write_mutex: AsyncMutex::new(()),
            data_manager,
        }
    }
}

// TODO: filter duplicated transaction before executing
#[async_trait::async_trait]
impl StateComputer for ExecutionProxy {
    async fn compute(
        &self,
        // The block to be executed.
        block: &Block,
        // The parent block id.
        parent_block_id: HashValue,
    ) -> Result<StateComputeResult, ExecutionError> {
        fail_point!("consensus::compute", |_| {
            Err(ExecutionError::InternalError {
                error: "Injected error in compute".into(),
            })
        });
        let block_id = block.id();
        debug!(
            block = %block,
            parent_id = parent_block_id,
            "Executing block",
        );

        debug!(
            "QSE: trying to get data., round {}, epoch: {} ",
            block.round(),
            block.epoch()
        );
        let txns = self.data_manager.get_data(block).await?;

        // TODO: figure out error handling for the prologue txn
        let executor = self.executor.clone();
        let transactions_to_execute =
            block.transactions_to_execute(&self.validators.lock(), txns.clone());
        let compute_result = monitor!(
            "execute_block",
            tokio::task::spawn_blocking(move || {
                info!(
                    "received block {} to execute, len: {}",
                    block_id,
                    transactions_to_execute.len()
                );
                /*
                let mut txn_status = Vec::new();
                txn_status.resize(
                    transactions_to_execute.len(),
                    TransactionStatus::Keep(ExecutionStatus::Success),
                );

                Ok::<StateComputeResult, executor_types::Error>(StateComputeResult::new(
                    parent_block_id,
                    Vec::new(),
                    0,
                    Vec::new(),
                    0,
                    None,
                    txn_status,
                    Vec::new(),
                    Vec::new(),
                ))*/
                executor.execute_block((block_id, transactions_to_execute), parent_block_id)
            })
            .await
        )
        .expect("spawn_blocking failed")?;

        observe_block(block.timestamp_usecs(), BlockStage::EXECUTED);

        // notify mempool about failed transaction
        if let Err(e) = self
            .txn_notifier
            .notify_failed_txn(txns, &compute_result)
            .await
        {
            error!(
                error = ?e, "Failed to notify mempool of rejected txns",
            );
        }
        Ok(compute_result)
    }

    /// Send a successful commit. A future is fulfilled when the state is finalized.
    async fn commit(
        &self,
        blocks: &[Arc<ExecutedBlock>],
        finality_proof: LedgerInfoWithSignatures,
        callback: StateComputerCommitCallBackType,
    ) -> Result<(), ExecutionError> {
        let _guard = self.write_mutex.lock().await;

        let mut block_ids = Vec::new();
        let mut txns = Vec::new();
        let mut reconfig_events = Vec::new();
        let skip_clean = blocks.is_empty();
        let mut latest_epoch: u64 = 0;
        let mut latest_round: u64 = 0;
        let mut payloads = Vec::new();

        for block in blocks {
            block_ids.push(block.id());
            if block.block().payload().is_some() {
                payloads.push(block.block().payload().unwrap().clone());
            }
            debug!("QSE: getting data in commit, round {}", block.round());
            let signed_txns = self.data_manager.get_data(block.block()).await?;

            txns.extend(block.transactions_to_commit(&self.validators.lock(), signed_txns));
            reconfig_events.extend(block.reconfig_event());

            latest_epoch = max(latest_epoch, block.epoch());
            latest_round = max(latest_round, block.round());
        }

        let executor = self.executor.clone();
        let proof = finality_proof.clone();
        monitor!(
            "commit_block",
            tokio::task::spawn_blocking(move || {
                executor
                    .commit_blocks_ext(block_ids, proof, false)
                    .expect("Failed to commit blocks");
            })
            .await
        )
        .expect("spawn_blocking failed");

        let blocks = blocks.to_vec();
        let wrapped_callback = move || {
            callback(&blocks, finality_proof);
        };
        self.async_state_sync_notifier
            .clone()
            .send((Box::new(wrapped_callback), txns, reconfig_events))
            .await
            .expect("Failed to send async state sync notification");

        // If there are no blocks, epoch and round will be invalid.
        // TODO: is this ever the case? why?
        if skip_clean {
            return Ok(());
        }
        debug!("QS: commit epoch {} round {}", latest_epoch, latest_round);

        self.async_commit_notifier
            .clone()
            .send((latest_epoch, latest_round, payloads))
            .await
            .expect("Failed to send async commit notification");
        Ok(())
    }

    /// Synchronize to a commit that not present locally.
    async fn sync_to(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        let _guard = self.write_mutex.lock().await;

        // Before the state synchronization, we have to call finish() to free the in-memory SMT
        // held by BlockExecutor to prevent memory leak.
        self.executor.finish();

        debug!(
            "QS: sync_to epoch {} round {}",
            target.ledger_info().epoch(),
            target.ledger_info().round()
        );
        self.async_commit_notifier
            .clone()
            .send((
                target.ledger_info().epoch(),
                target.ledger_info().round(),
                Vec::new(),
            ))
            .await
            .expect("Failed to send async commit notification in fast_sync_forward");

        fail_point!("consensus::sync_to", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to").into())
        });
        // Here to start to do state synchronization where ChunkExecutor inside will
        // process chunks and commit to Storage. However, after block execution and
        // commitments, the sync state of ChunkExecutor may be not up to date so
        // it is required to reset the cache of ChunkExecutor in State Sync
        // when requested to sync.
        let res = monitor!(
            "sync_to",
            self.state_sync_notifier.sync_to_target(target).await
        );

        // Similarly, after the state synchronization, we have to reset the cache
        // of BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;

        res.map_err(|error| {
            let anyhow_error: anyhow::Error = error.into();
            anyhow_error.into()
        })
    }

    fn new_epoch(&self, epoch_state: &EpochState) {
        *self.validators.lock() = epoch_state
            .verifier
            .get_ordered_account_addresses_iter()
            .collect();
    }
}
