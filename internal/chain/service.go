package chain

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/0xEmmyb2/CipherPass/pkg/bindings"
	"github.com/0xEmmyb2/CipherPass/pkg/database"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	
	// ZK packages are commented out until they are published or moved to internal
	// "github.com/consensys/gnark-crypto/ecc"
	// gcmimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	// "github.com/consensys/gnark/backend/groth16"
	// "github.com/consensys/gnark/backend/witness"
	// "github.com/consensys/gnark/constraint"
	// "github.com/consensys/gnark/frontend"
	// "github.com/cipherpass/zk/circuits/licenseproof"
	// "github.com/cipherpass/zk/gadgets/merkle"
	// "github.com/cipherpass/zk/prover"
)

// Service provides high-level blockchain operations.
type Service struct {
	client   *Client
	license  *bindings.LicenseRegistry
	credReg  *bindings.CredentialRegistry
	audit    *bindings.AuditAnchor
	db       *database.MongoDB
	logger   config.LoggerInterface
	cfg      config.ChainConfig
}

// NewService creates a chain service with all contract bindings.
func NewService(db *database.MongoDB, logger config.LoggerInterface, cfg config.ChainConfig, signer Signer) (*Service, error) {
	// Validate contract addresses
	if !ValidateAddress(cfg.LicenseRegistry) {
		return nil, fmt.Errorf("contract address LicenseRegistry is not configured (zero address)")
	}
	if !ValidateAddress(cfg.CredentialRegistry) {
		return nil, fmt.Errorf("contract address CredentialRegistry is not configured (zero address)")
	}
	if !ValidateAddress(cfg.AuditAnchor) {
		return nil, fmt.Errorf("contract address AuditAnchor is not configured (zero address)")
	}

	// Create RPC client
	client, err := NewClient(cfg, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain client: %w", err)
	}

	// Create contract bindings
	license, err := bindings.NewLicenseRegistry(cfg.LicenseRegistry)
	if err != nil {
		return nil, fmt.Errorf("failed to bind LicenseRegistry: %w", err)
	}
	credReg, err := bindings.NewCredentialRegistry(cfg.CredentialRegistry)
	if err != nil {
		return nil, fmt.Errorf("failed to bind CredentialRegistry: %w", err)
	}
	audit, err := bindings.NewAuditAnchor(cfg.AuditAnchor)
	if err != nil {
		return nil, fmt.Errorf("failed to bind AuditAnchor: %w", err)
	}

	return &Service{
		client:  client,
		license: license,
		credReg: credReg,
		audit:   audit,
		db:      db,
		logger:  logger,
		cfg:     cfg,
	}, nil
}

// --- License Issuance ---

// IssueLicenseResult contains the result of a license issuance.
type IssueLicenseResult struct {
	Keccak256Leaf [32]byte `json:"keccak256_leaf"`
	MiMCLeaf      []byte   `json:"mimc_leaf"`
	LeafIndex     int64    `json:"leaf_index"`
	TxHash        string   `json:"tx_hash"`
}

// IssueLicense issues a new license on-chain and stores the dual-hash in Postgres.
// This is the main entry point for the "Issue License" admin action.
func (s *Service) IssueLicense(ctx context.Context, userID string, record LicenseRecord) (*IssueLicenseResult, error) {
	// 1. Compute both leaf hashes
	keccakLeaf := ComputeKeccak256Leaf(record)
	mimcLeaf := ComputeMiMCLeaf(record)

	s.logger.WithFields(map[string]interface{}{
		"user_id":        userID,
		"licence_number": record.LicenceNumber,
	}).Info("Computing license leaf hashes")

	// 2. Check if already issued
	alreadyIssued, err := s.isLeafIssued(ctx, keccakLeaf)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing issuance: %w", err)
	}
	if alreadyIssued {
		return nil, fmt.Errorf("license already issued for this leaf hash")
	}

	// 3. Build and send the issueLicense transaction
	nonce, err := s.client.PendingNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}

	gasPrice, err := s.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %w", err)
	}

	calldata, err := s.license.PackIssueLicense(keccakLeaf)
	if err != nil {
		return nil, fmt.Errorf("failed to pack issueLicense call: %w", err)
	}

	tx := NewTransaction(
		nonce,
		s.cfg.LicenseRegistry,
		big.NewInt(0), // No ETH value
		200_000,        // Gas limit
		gasPrice,
		calldata,
	)

	signedTx, err := s.client.SendSignedTransaction(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to send issueLicense transaction: %w", err)
	}

	s.logger.WithField("tx_hash", signedTx.Hash().Hex()).Info("issueLicense transaction sent")

	// 4. Store the dual-hash in MongoDB (before on-chain confirmation)
	//    The event listener will update leaf_index and on_chain_root when confirmed.
	userUUID, _ := uuid.Parse(userID)
	leafRecord := LicenseLeaf{
		ID:            uuid.New(),
		UserID:        userUUID,
		LicenceNumber: record.LicenceNumber,
		Keccak256Leaf: keccakLeaf[:],
		MiMCLeaf:      mimcLeaf,
		IssuedAt:      time.Now(),
	}
	_, err = s.db.Collection("license_leaves").InsertOne(ctx, leafRecord)
	if err != nil {
		s.logger.WithError(err).Error("Failed to store license leaf in MongoDB")
		// Transaction was sent — don't return error, the event listener will sync
	}

	// 5. Insert into shadow Merkle tree
	if err := s.insertIntoShadowTree(ctx, mimcLeaf); err != nil {
		s.logger.WithError(err).Error("Failed to insert into shadow Merkle tree")
	}

	return &IssueLicenseResult{
		Keccak256Leaf: keccakLeaf,
		MiMCLeaf:      mimcLeaf,
		TxHash:        signedTx.Hash().Hex(),
	}, nil
}

// isLeafIssued checks if a leaf hash has already been issued on-chain.
func (s *Service) isLeafIssued(ctx context.Context, leafHash [32]byte) (bool, error) {
	calldata, err := s.license.ABI.Pack("isIssued", leafHash)
	if err != nil {
		return false, err
	}

	msg := s.client.BuildContractCall(s.cfg.LicenseRegistry, calldata)
	result, err := s.client.CallContract(ctx, msg)
	if err != nil {
		return false, err
	}

	return s.license.UnpackIsIssued(result)
}

// --- Credential Status ---

// CredentialStatus represents the on-chain credential status.
type CredentialStatus uint8

const (
	StatusNone     CredentialStatus = CredentialStatus(bindings.CredentialNone)
	StatusActive   CredentialStatus = CredentialStatus(bindings.CredentialActive)
	StatusRevoked  CredentialStatus = CredentialStatus(bindings.CredentialRevoked)
	StatusSuspended CredentialStatus = CredentialStatus(bindings.CredentialSuspended)
)

// CheckCredentialStatus returns the on-chain status of a credential.
func (s *Service) CheckCredentialStatus(ctx context.Context, credentialHash [32]byte) (CredentialStatus, error) {
	calldata, err := s.credReg.PackCheckStatus(credentialHash)
	if err != nil {
		return StatusNone, err
	}

	msg := s.client.BuildContractCall(s.cfg.CredentialRegistry, calldata)
	result, err := s.client.CallContract(ctx, msg)
	if err != nil {
		return StatusNone, err
	}

	status, err := s.credReg.UnpackCheckStatus(result)
	if err != nil {
		return StatusNone, err
	}

	return CredentialStatus(status), nil
}

// IsCredentialActive is a convenience check: returns true only if status == ACTIVE.
func (s *Service) IsCredentialActive(ctx context.Context, credentialHash [32]byte) (bool, error) {
	status, err := s.CheckCredentialStatus(ctx, credentialHash)
	return status == StatusActive, err
}

// --- Audit Anchoring ---

// AnchorAuditBatch anchors a batch of audit log entries on-chain.
// batchRoot is the Merkle root computed over the batch's log entry hashes.
func (s *Service) AnchorAuditBatch(ctx context.Context, batchID *big.Int, batchRoot [32]byte) (string, error) {
	nonce, err := s.client.PendingNonce(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get nonce: %w", err)
	}

	gasPrice, err := s.client.SuggestGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to suggest gas price: %w", err)
	}

	calldata, err := s.audit.PackAnchorBatch(batchID, batchRoot)
	if err != nil {
		return "", fmt.Errorf("failed to pack anchorBatch call: %w", err)
	}

	tx := NewTransaction(
		nonce,
		s.cfg.AuditAnchor,
		big.NewInt(0),
		100_000,
		gasPrice,
		calldata,
	)

	signedTx, err := s.client.SendSignedTransaction(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("failed to send anchorBatch transaction: %w", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"batch_id": batchID.String(),
		"tx_hash":  signedTx.Hash().Hex(),
	}).Info("Audit batch anchored on-chain")

	return signedTx.Hash().Hex(), nil
}

// --- Shadow Merkle Tree (ZK) ---

// GetShadowTreeRoot returns the current root of the ZK shadow Merkle tree.
// GetShadowTreeRoot returns the current root of the ZK shadow Merkle tree.
func (s *Service) GetShadowTreeRoot(ctx context.Context) ([]byte, error) {
	var state ShadowMerkleState
	err := s.db.Collection("shadow_merkle_state").FindOne(ctx, bson.M{"_id": "default"}).Decode(&state)
	if err != nil {
		return nil, err
	}
	return state.Root, nil
}

// GetShadowTreeSiblings returns the Merkle path (sibling hashes) for a given leaf index
// in the shadow tree. Used by the ZK prover to generate inclusion proofs.
func (s *Service) GetShadowTreeSiblings(ctx context.Context, leafIndex int64) ([][]byte, error) {
	siblings := make([][]byte, TreeDepth)
	zeros := emptyTreeRoots()
	for level := 0; level < TreeDepth; level++ {
		siblingPos := leafIndex
		if (leafIndex>>uint(level))%2 == 0 {
			siblingPos = leafIndex | (1 << uint(level))
		} else {
			siblingPos = leafIndex &^ (1 << uint(level))
		}

		var node ShadowMerkleNode
		err := s.db.Collection("shadow_merkle_nodes").FindOne(ctx, bson.M{"level": level, "position": siblingPos}).Decode(&node)
		if err != nil {
			siblings[level] = zeros[level][:]
		} else {
			siblings[level] = node.Hash
		}
	}
	return siblings, nil
}

// insertIntoShadowTree adds a new leaf to the shadow Merkle tree and recomputes affected nodes.
func (s *Service) insertIntoShadowTree(ctx context.Context, leafHash []byte) error {
	var state ShadowMerkleState
	err := s.db.Collection("shadow_merkle_state").FindOne(ctx, bson.M{"_id": "default"}).Decode(&state)
	if err != nil {
		return err
	}

	leafIndex := state.NextIndex
	zeros := emptyTreeRoots()
	now := time.Now()

	_, err = s.db.Collection("shadow_merkle_nodes").UpdateOne(ctx,
		bson.M{"level": 0, "position": leafIndex},
		bson.M{"$set": bson.M{"hash": leafHash, "updated_at": now}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		return err
	}

	currentHash := leafHash
	for level := 0; level < TreeDepth; level++ {
		var siblingHash []byte
		var siblingPos int64

		if (leafIndex>>uint(level))%2 == 0 {
			siblingPos = leafIndex | (1 << uint(level))
			var node ShadowMerkleNode
			err := s.db.Collection("shadow_merkle_nodes").FindOne(ctx, bson.M{"level": level, "position": siblingPos}).Decode(&node)
			if err != nil {
				siblingHash = zeros[level][:]
			} else {
				siblingHash = node.Hash
			}
			parentHash := mimcHash(append(currentHash, siblingHash...))
			parentPos := leafIndex >> uint(level+1)
			currentHash = parentHash
			_, err = s.db.Collection("shadow_merkle_nodes").UpdateOne(ctx,
				bson.M{"level": level + 1, "position": parentPos},
				bson.M{"$set": bson.M{"hash": parentHash, "updated_at": now}},
				options.Update().SetUpsert(true),
			)
			if err != nil {
				return err
			}
		} else {
			siblingPos = leafIndex &^ (1 << uint(level))
			var node ShadowMerkleNode
			err := s.db.Collection("shadow_merkle_nodes").FindOne(ctx, bson.M{"level": level, "position": siblingPos}).Decode(&node)
			if err != nil {
				siblingHash = zeros[level][:]
			} else {
				siblingHash = node.Hash
			}
			parentHash := mimcHash(append(siblingHash, currentHash...))
			parentPos := leafIndex >> uint(level+1)
			currentHash = parentHash
			_, err = s.db.Collection("shadow_merkle_nodes").UpdateOne(ctx,
				bson.M{"level": level + 1, "position": parentPos},
				bson.M{"$set": bson.M{"hash": parentHash, "updated_at": now}},
				options.Update().SetUpsert(true),
			)
			if err != nil {
				return err
			}
		}
	}

	_, err = s.db.Collection("shadow_merkle_state").UpdateOne(ctx,
		bson.M{"_id": "default"},
		bson.M{"$set": bson.M{"root": currentHash, "next_index": leafIndex + 1, "updated_at": now}},
	)
	if err != nil {
		return err
	}

	s.logger.WithField("leaf_index", leafIndex).Info("Shadow Merkle tree updated")
	return nil
}

// GetClient returns the underlying chain client for use by the event listener.
func (s *Service) GetClient() *Client {
	return s.client
}

// GetLicenseRegistry returns the LicenseRegistry binding for the event listener.
func (s *Service) GetLicenseRegistry() *bindings.LicenseRegistry {
	return s.license
}

// --- Database helpers for event sync ---

// GetLastSyncedBlock returns the last processed block for a given contract.
func (s *Service) GetLastSyncedBlock(ctx context.Context, contractID string) (int64, error) {
	var sync ChainEventSync
	err := s.db.Collection("chain_event_sync").FindOne(ctx, bson.M{"_id": contractID}).Decode(&sync)
	if err != nil {
		return 0, nil
	}
	return sync.LastBlock, nil
}

// UpdateSyncedBlock updates the last processed block for a given contract.
func (s *Service) UpdateSyncedBlock(ctx context.Context, contractID string, blockNum int64) error {
	_, err := s.db.Collection("chain_event_sync").UpdateOne(ctx,
		bson.M{"_id": contractID},
		bson.M{"$set": bson.M{"last_block": blockNum, "updated_at": time.Now()}},
		options.Update().SetUpsert(true),
	)
	return err
}

// GetLicenseLeafByKeccak looks up a license leaf by its on-chain keccak256 hash.
func (s *Service) GetLicenseLeafByKeccak(ctx context.Context, leafHash [32]byte) (*LicenseLeaf, error) {
	var leaf LicenseLeaf
	err := s.db.Collection("license_leaves").FindOne(ctx, bson.M{"keccak256_leaf": leafHash[:]}).Decode(&leaf)
	if err != nil {
		return nil, err
	}
	return &leaf, nil
}

// GetLicenseLeafByUserID looks up a license leaf by user ID.
func (s *Service) GetLicenseLeafByUserID(ctx context.Context, userID uuid.UUID) (*LicenseLeaf, error) {
	var leaf LicenseLeaf
	err := s.db.Collection("license_leaves").FindOne(ctx, bson.M{"user_id": userID}).Decode(&leaf)
	if err != nil {
		return nil, err
	}
	return &leaf, nil
}

// getHolderIdentityCommitment returns the holder identity commitment for a user.
// This is a zero-knowledge friendly commitment to the user's identity data.
func (s *Service) getHolderIdentityCommitment(userID uuid.UUID) (string, error) {
	// TODO: Replace with actual implementation that retrieves or computes
	// the holder identity commitment from verified user data (biometrics, documents)
	// For now, return a deterministic placeholder based on userID
	hash := sha256.Sum256(append([]byte("holder-identity-commitment:"), userID[:]...))
	return fmt.Sprintf("%x", hash), nil
}

// getLicenseCategory returns the license category for a user.
// This represents the type/class of license (e.g., 1=motorcycle, 2=car, 3=truck).
func (s *Service) getLicenseCategory(userID uuid.UUID) (int64, error) {
	// TODO: Replace with actual implementation that retrieves the license category
	// from user data or license records
	// For now, return a default category (e.g., 2 for car)
	return 2, nil
}

// calculateExpiryDate calculates the expiry date based on the issued date.
// Assumes a fixed validity period (e.g., 5 years).
func (s *Service) calculateExpiryDate(issuedAt time.Time) (int64, error) {
	// TODO: Replace with actual validity period logic (may depend on license category, jurisdiction, etc.)
	// For now, assume 5 years validity
	validityPeriod := int64(5 * 365 * 24 * 60 * 60) // 5 years in seconds
	return issuedAt.Unix() + validityPeriod, nil
}

// GenerateLicenseVerificationProof generates a ZK proof proving that a user's license
// is valid and meets the specified requirements, without revealing the underlying license data.
// This is used when a driver presents their QR code for license verification.
func (s *Service) GenerateLicenseVerificationProof(ctx context.Context, userID uuid.UUID, requiredCategory int64, currentTimestamp int64) (any, any, error) {
	leaf, err := s.GetLicenseLeafByUserID(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get license leaf for user %s: %w", userID, err)
	}

	_, err = s.getHolderIdentityCommitment(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get holder identity commitment: %w", err)
	}

	_ = leaf
	return nil, nil, fmt.Errorf("ZK proof generation module is pending integration")
}
