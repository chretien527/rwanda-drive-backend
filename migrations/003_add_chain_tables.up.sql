-- License leaves: stores the dual-hash (keccak256 + MiMC) mapping for every issued license.
-- keccak256 leaf is what's on-chain in LicenseRegistry.sol.
-- miMC leaf is what's used by the ZK shadow Merkle tree for privacy-preserving proofs.
CREATE TABLE license_leaves (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    licence_number VARCHAR(50) NOT NULL,
    keccak256_leaf BYTEA NOT NULL UNIQUE,       -- on-chain leaf hash
    miMC_leaf BYTEA NOT NULL UNIQUE,             -- ZK shadow tree leaf hash
    leaf_index BIGINT,                           -- index in the on-chain tree (NULL until confirmed on-chain)
    on_chain_root BYTEA,                         -- root at time of issuance (NULL until confirmed)
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    synced_at TIMESTAMPTZ                        -- last time event listener confirmed on-chain status
);

CREATE INDEX idx_license_leaves_user_id ON license_leaves(user_id);
CREATE INDEX idx_license_leaves_keccak256 ON license_leaves(keccak256_leaf);
CREATE INDEX idx_license_leaves_miMC ON license_leaves(miMC_leaf);

-- Shadow Merkle tree nodes: Postgres-backed storage for the ZK Merkle tree.
-- The ZK prover needs to generate MiMC Merkle paths on demand.
-- This mirrors LicenseRegistry.sol's on-chain tree but using MiMC instead of keccak256.
CREATE TABLE shadow_merkle_nodes (
    level INT NOT NULL,
    position BIGINT NOT NULL,
    hash BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (level, position)
);

CREATE INDEX idx_shadow_merkle_nodes_level ON shadow_merkle_nodes(level);

-- Track the shadow tree's current state
CREATE TABLE shadow_merkle_state (
    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1), -- single row
    root BYTEA NOT NULL,
    next_index BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert initial state (empty tree root will be computed by the application)
INSERT INTO shadow_merkle_state (root, next_index) VALUES (E'\\x00', 0);

-- On-chain event sync tracking
CREATE TABLE chain_event_sync (
    id VARCHAR(50) PRIMARY KEY,                  -- contract name (e.g., 'LicenseRegistry')
    last_block BIGINT NOT NULL DEFAULT 0,        -- last processed block number
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Initialize sync cursors for each contract we listen to
INSERT INTO chain_event_sync (id, last_block) VALUES ('LicenseRegistry', 0);
INSERT INTO chain_event_sync (id, last_block) VALUES ('CredentialRegistry', 0);
INSERT INTO chain_event_sync (id, last_block) VALUES ('AuditAnchor', 0);
