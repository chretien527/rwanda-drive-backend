package chain

import (
	"time"

	"github.com/google/uuid"
)

// LicenseLeaf stores the dual-hash mapping for an issued license.
// keccak256_leaf is what's on-chain in LicenseRegistry.sol.
// miMC_leaf is what's used by the ZK shadow Merkle tree.
type LicenseLeaf struct {
	ID             uuid.UUID  `json:"id"`
	UserID         uuid.UUID  `json:"user_id"`
	LicenceNumber  string     `json:"licence_number"`
	Keccak256Leaf  []byte     `json:"keccak256_leaf"`  // 32 bytes
	MiMCLeaf       []byte     `json:"mimc_leaf"`        // 32 bytes
	LeafIndex      *int64     `json:"leaf_index,omitempty"`
	OnChainRoot    []byte     `json:"on_chain_root,omitempty"`
	IssuedAt       time.Time  `json:"issued_at"`
	SyncedAt       *time.Time `json:"synced_at,omitempty"`
}

// ShadowMerkleNode stores a single node in the ZK shadow Merkle tree.
type ShadowMerkleNode struct {
	Level    int       `json:"level"`
	Position int64     `json:"position"`
	Hash     []byte    `json:"hash"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ShadowMerkleState tracks the current state of the shadow Merkle tree.
type ShadowMerkleState struct {
	Root      []byte    `json:"root"`
	NextIndex int64     `json:"next_index"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ChainEventSync tracks the last processed block for each contract's event listener.
type ChainEventSync struct {
	ID        string    `json:"id"`
	LastBlock int64     `json:"last_block"`
	UpdatedAt time.Time `json:"updated_at"`
}

// LicenseRecord is the raw license data needed to compute both leaf hashes.
type LicenseRecord struct {
	LicenceNumber            string
	HolderIdentityCommitment string
	Category                 int64
	IssueDate                int64 // Unix timestamp
	ExpiryDate               int64 // Unix timestamp
}
