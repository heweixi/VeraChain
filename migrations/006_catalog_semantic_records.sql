CREATE TABLE IF NOT EXISTS pending_catalog_records (
    record_id TEXT PRIMARY KEY NOT NULL,
    data TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS catalog_subjects (
    subject_id TEXT PRIMARY KEY NOT NULL,
    subject_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    issuer_identity TEXT NOT NULL,
    issuer_key TEXT NOT NULL,
    record_id TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    block_index INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS catalog_revisions (
    revision_id TEXT PRIMARY KEY NOT NULL,
    subject_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    parent_revision_id TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    issuer_identity TEXT NOT NULL,
    issuer_key TEXT NOT NULL,
    record_id TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    block_index INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS catalog_artifacts (
    artifact_id TEXT PRIMARY KEY NOT NULL,
    revision_id TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    configuration_hash TEXT NOT NULL,
    platform TEXT NOT NULL,
    issuer_identity TEXT NOT NULL,
    issuer_key TEXT NOT NULL,
    record_id TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    block_index INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS catalog_claims (
    claim_id TEXT PRIMARY KEY NOT NULL,
    subject_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    effective_from INTEGER,
    effective_to INTEGER,
    supersedes_claim_id TEXT NOT NULL,
    issuer_identity TEXT NOT NULL,
    issuer_key TEXT NOT NULL,
    record_id TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    block_index INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_catalog_pending_created_at ON pending_catalog_records(created_at);
CREATE INDEX IF NOT EXISTS idx_catalog_revisions_subject ON catalog_revisions(subject_id);
CREATE INDEX IF NOT EXISTS idx_catalog_artifacts_revision ON catalog_artifacts(revision_id);
CREATE INDEX IF NOT EXISTS idx_catalog_claims_subject ON catalog_claims(subject_id);
CREATE INDEX IF NOT EXISTS idx_catalog_claims_revision ON catalog_claims(revision_id);
CREATE INDEX IF NOT EXISTS idx_catalog_claims_artifact ON catalog_claims(artifact_id);
CREATE INDEX IF NOT EXISTS idx_catalog_claims_category_status ON catalog_claims(category, status);
CREATE INDEX IF NOT EXISTS idx_catalog_claims_effective ON catalog_claims(effective_from, effective_to);
