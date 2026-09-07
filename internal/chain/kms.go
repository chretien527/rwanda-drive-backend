package chain

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Signer abstracts transaction signing — implemented by KMS or local key.
// In production, the private key never leaves the KMS; the backend calls
// KMS.SignTransactionDigest() and receives the signature bytes.
type Signer interface {
	// Address returns the signer's Ethereum address (derived from the public key).
	Address() common.Address
	// SignTransaction signs a transaction and returns the signed transaction.
	SignTransaction(ctx context.Context, chainID *big.Int, tx *types.Transaction) (*types.Transaction, error)
}

// LocalSigner is a development/testing signer using a local private key.
// NEVER use this in production — the key is held in process memory.
type LocalSigner struct {
	key *ecdsa.PrivateKey
}

// NewLocalSigner creates a signer from a hex-encoded private key (for dev only).
func NewLocalSigner(hexKey string) (*LocalSigner, error) {
	key, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	return &LocalSigner{key: key}, nil
}

// Address returns the Ethereum address derived from the private key.
func (s *LocalSigner) Address() common.Address {
	return crypto.PubkeyToAddress(s.key.PublicKey)
}

// SignTransaction signs a transaction using the local private key.
func (s *LocalSigner) SignTransaction(ctx context.Context, chainID *big.Int, tx *types.Transaction) (*types.Transaction, error) {
	signer := types.NewEIP155Signer(chainID)
	return types.SignTx(tx, signer, s.key)
}

// KMSSigner is a placeholder for a real KMS-backed signer.
// In production, this would call AWS KMS Sign or GCP Cloud KMS SignRaw
// using the KMS key's asymmetric key pair. The KMS never exports the
// private key — it signs a digest and returns (r, s, v).
type KMSSigner struct {
	keyID    string
	region   string
	provider string
}

// NewKMSSigner creates a KMS signer from configuration.
func NewKMSSigner(keyID, region, provider string) (*KMSSigner, error) {
	if keyID == "" {
		return nil, fmt.Errorf("KMS key ID is required")
	}
	return &KMSSigner{
		keyID:    keyID,
		region:   region,
		provider: provider,
	}, nil
}

// Address returns the platform signer address.
// In production, this would be derived from the KMS public key.
// For now, it returns a placeholder that must be configured via env.
func (s *KMSSigner) Address() common.Address {
	// TODO: Fetch the public key from KMS on startup and derive address
	return common.Address{}
}

// SignTransaction signs a transaction via KMS.
// TODO: Implement real KMS signing:
// 1. Build the signing payload (RLP-encoded unsigned tx)
// 2. Send digest to KMS via Sign API
// 3. Reconstruct the signed tx from the returned signature
func (s *KMSSigner) SignTransaction(ctx context.Context, chainID *big.Int, tx *types.Transaction) (*types.Transaction, error) {
	// Placeholder: in production, call KMS API here
	return nil, fmt.Errorf("KMS signing not yet implemented — use local signer for development")
}

// Helper: NewTransaction builds an unsigned transaction.
func NewTransaction(nonce uint64, to common.Address, value *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *types.Transaction {
	return types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
}
