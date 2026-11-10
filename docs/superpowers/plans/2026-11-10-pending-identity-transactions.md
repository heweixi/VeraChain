# Pending Identity Transactions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist accepted identity key transactions in SQLite so restart, retry, and mining preserve exactly-once idempotency behavior.

**Architecture:** Migration 007 adds an identity transaction ledger that stores the signed entry, submitter, request fingerprint, acceptance ordering, and `pending`/`committed` state. The chain carries ledger IDs only as an internal sidecar, while block `key_transactions` and Merkle leaves remain exactly the existing signed entries. The HTTP handler serializes submit/mining transitions with an application gate; SQLite enforces durable idempotency with a partial unique index and commits ledger state in the existing block transaction.

**Tech Stack:** Rust 2021, Axum 0.7, SQLx SQLite, Tokio, existing Tower integration tests.

**Spec:** `.team-logs/sessions/20261110-173828-pending-identity-tx/03-architect-175452.md`

## Global Constraints

- Keep existing key-transaction request JSON, Ed25519 signing payload, `Block::key_transactions`, block JSON, and Merkle calculation unchanged.
- `Idempotency-Key` is optional; requests without it retain the prior accepted-pending behavior and have no strong duplicate guarantee.
- Same authenticated user plus non-empty key must have one durable ledger row across retries, restart, and concurrent in-process requests.
- First accepted pending order is `(accepted_at, transaction_id)`; no generated ledger ID enters a block or Merkle root.
- A retry of pending returns HTTP 202; a retry of committed returns HTTP 200; reuse of a key with a different request fingerprint returns HTTP 409.
- Block insertion and every included ledger row's state transition to committed occur in one SQLite transaction. Legacy pending rows found in history at startup fail closed.
- Preserve existing RBAC route protection and CORS compatibility while allowing `Idempotency-Key` from browser clients.
- Rust validation runs only on 247 with Docker `rust:latest` and the retained cache volumes.

## Review Focus

- Header value is absent, blank, or non-ASCII: it must be treated as no idempotency key, not stored as an invalid durable identity.
- A different signed request reuses the same authenticated user's key: it must return 409 and must not enter the pending queue.
- Two users use the same key: their ledgers must remain independent.
- A storage commit error after mining: in-memory chain and pending sidecars must roll back together without marking any identity ledger row committed.
- Startup finds a `pending` row whose exact entry already appears in a committed block: initialization must fail before loading or mutating pending rows.

---

### Task 1: Durable identity transaction ledger

**Files:**
- Create: `migrations/007_identity_transactions.sql`
- Modify: `src/storage/database.rs`
- Test: `src/storage/database.rs`

**Interfaces:**
- Produces: `PendingKeyTransaction { transaction_id: String, entry: KeyTransactionEntry }`, `StoredIdentityTransaction`, `Storage::create_or_get_identity_transaction`, `Storage::get_pending_identity_transactions`, and `Storage::commit_block(block, identity_transaction_ids)`.

- [ ] **Step 1: Write failing storage tests**

Test durable create/replay of one signed entry, same-user/key collision with a different fingerprint, ordering by acceptance time and ID, and block commit changing only supplied rows from pending to committed.

- [ ] **Step 2: Run the focused storage tests on 247 to verify RED**

Run the added test filter through Docker `rust:latest` after pushing the test-only commit. Expected: compilation fails because ledger types/methods and the extended commit contract do not exist.

- [ ] **Step 3: Add migration 007 and minimal storage ledger interface**

Store transaction ID, nullable key, submitter user ID, request fingerprint, serialized `KeyTransactionEntry`, accepted timestamp, state, and nullable committed block index. Use a partial unique index for non-null keys scoped to submitter. Make `commit_block` write the block and update only listed pending IDs in its existing transaction.

- [ ] **Step 4: Run focused storage tests on 247 to verify GREEN**

Expected: all new storage tests pass with the existing storage suite.

### Task 2: Pending sidecar queue and restart recovery

**Files:**
- Modify: `src/core/chain.rs`
- Modify: `src/cli/server.rs`
- Test: `src/core/chain.rs`
- Test: `tests/api_integration.rs`

**Interfaces:**
- Consumes: `Vec<PendingKeyTransaction>` from storage.
- Produces: `Chain::add_pending_key_transaction`, `Chain::load_pending_key_transactions`, `Chain::mine_block_with_identity_transaction_ids`, and rollback preserving entry/ID alignment.

- [ ] **Step 1: Write failing chain/restart tests**

Test mined blocks retain existing entry-only key transactions while returning ordered sidecar IDs; test rollback restores the same sidecars; test a restarted state reloads durable pending transactions in acceptance order; test a legacy pending entry already present in history fails closed.

- [ ] **Step 2: Run focused tests on 247 to verify RED**

Expected: missing sidecar/recovery methods or the old mining return contract cause failures.

- [ ] **Step 3: Implement sidecar queue and recovery validation**

Keep the sidecar private to chain/storage coordination, drain its entries alongside the existing pending key queue, and validate history before `load_pending_key_transactions`. Update server startup after committed-chain validation and before application state construction.

- [ ] **Step 4: Run focused tests on 247 to verify GREEN**

Expected: sidecar, rollback, restart ordering, and fail-closed tests pass.

### Task 3: Idempotent HTTP submission and atomic mining

**Files:**
- Modify: `src/api/state.rs`
- Modify: `src/api/routes.rs`
- Modify: `src/api/handlers.rs`
- Modify: `tests/api_integration.rs`
- Modify: `tests/websocket_integration.rs`

**Interfaces:**
- Consumes: optional `Idempotency-Key` and authenticated `Claims.sub`.
- Produces: accepted response containing `transaction_id` and `status`, 202 pending replay, 200 committed replay, and 409 fingerprint conflict.

- [ ] **Step 1: Write failing API behavior tests**

Test first keyed submission returns 202, same request returns 202 without a second queue item, a post-mining retry returns 200 committed, key reuse with changed request returns 409, and the existing no-header request remains 202. Update test request helpers and AppState literals for the new gate only as needed.

- [ ] **Step 2: Run focused API tests on 247 to verify RED**

Expected: header is ignored and response lacks transaction status/ID, so idempotent replay assertions fail.

- [ ] **Step 3: Implement the minimal handler/state changes**

Add an `Arc<tokio::sync::Mutex<()>>` gate to `AppState`, validate and build the signed entry before persistence, derive a deterministic fingerprint from the request's signed fields, and create/read the ledger under the gate. Mine under the same gate and pass returned sidecar IDs to transactional storage commit; rollback the mined block on storage error. Add the header to CORS allow-list.

- [ ] **Step 4: Run focused API tests on 247 to verify GREEN**

Expected: new replay behavior passes and existing RBAC/signature behavior remains unchanged.

### Task 4: Full verification

**Files:**
- Modify: all files above only.

- [ ] **Step 1: Format and inspect the diff**

Run `cargo fmt --check` in 247 Docker and inspect `git diff --check` locally.

- [ ] **Step 2: Run complete Rust verification on 247**

Run `cargo test --lib`, `cargo test --test api_integration`, `cargo test --test websocket_integration`, `cargo check --lib`, and `cargo clippy --lib -- -D warnings` using the retained 247 cache volumes.

- [ ] **Step 3: Report exact results and remaining risk**

Report all RED/GREEN evidence, migration compatibility limits, and any verification output that does not pass.
