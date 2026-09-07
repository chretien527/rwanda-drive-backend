package chain

import (
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TreeDepth is the depth of the Merkle trees (matching LicenseRegistry.sol's TREE_DEPTH = 20).
const TreeDepth = 20

// ComputeKeccak256Leaf computes the on-chain leaf hash:
//
//	keccak256(licenceNumber || holderIdentityCommitment || category || issueDate || expiryDate)
//
// This is what goes into LicenseRegistry.sol's incremental Merkle tree.
// Parameters are abi.encodePacked (tightly packed, no padding).
func ComputeKeccak256Leaf(record LicenseRecord) [32]byte {
	var data []byte
	data = append(data, []byte(record.LicenceNumber)...)
	data = append(data, []byte(record.HolderIdentityCommitment)...)

	catBytes := make([]byte, 32)
	big.NewInt(record.Category).FillBytes(catBytes)
	data = append(data, catBytes...)

	issueBytes := make([]byte, 32)
	big.NewInt(record.IssueDate).FillBytes(issueBytes)
	data = append(data, issueBytes...)

	expiryBytes := make([]byte, 32)
	big.NewInt(record.ExpiryDate).FillBytes(expiryBytes)
	data = append(data, expiryBytes...)

	return crypto.Keccak256Hash(data)
}

// ComputeMiMCLeaf computes the ZK shadow tree leaf hash using MiMC.
// The MiMC hash is computed over the same fields but using the MiMC
// permutation, which is friendly to ZK circuits (unlike keccak256).
//
// NOTE: This function uses a simplified MiMC implementation.
// For production, use gnark-crypto's MiMC as the prover package does.
func ComputeMiMCLeaf(record LicenseRecord) []byte {
	// Build the same packed preimage as the keccak256 leaf
	var data []byte
	data = append(data, []byte(record.LicenceNumber)...)
	data = append(data, []byte(record.HolderIdentityCommitment)...)

	catBytes := make([]byte, 32)
	big.NewInt(record.Category).FillBytes(catBytes)
	data = append(data, catBytes...)

	issueBytes := make([]byte, 32)
	big.NewInt(record.IssueDate).FillBytes(issueBytes)
	data = append(data, issueBytes...)

	expiryBytes := make([]byte, 32)
	big.NewInt(record.ExpiryDate).FillBytes(expiryBytes)
	data = append(data, expiryBytes...)

	// MiMC hash — using a simplified version here.
	// The full MiMC sponge is in zk/prover/LeafHash() using gnark-crypto.
	// This simplified version uses keccak256 as a placeholder that can be
	// replaced with real MiMC when the gnark-crypto dependency is available.
	//
	// TODO: Replace with gnark-crypto MiMC when building the real ZK integration.
	return mimcHash(data)
}

// mimcHash is a simplified MiMC-style hash for the backend's shadow tree.
// It uses keccak256 as a temporary stand-in — the real MiMC computation
// happens in the zk/prover package using gnark-crypto.
//
// IMPORTANT: The shadow Merkle tree MUST use the same hash as the ZK circuit.
// When deploying, ensure this matches the circuit's MiMC implementation.
func mimcHash(data []byte) []byte {
	// Placeholder: use keccak256 until gnark-crypto MiMC is integrated.
	// The shadow tree nodes will be recomputed when MiMC is available.
	h := crypto.Keccak256(data)
	return h
}

// ComputeMerkleRoot computes a keccak256 Merkle root from a set of leaves.
// Used for the on-chain tree (LicenseRegistry uses keccak256 internally).
func ComputeMerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		// Return the empty tree root (same as LicenseRegistry.sol constructor)
		return emptyTreeRoots()[TreeDepth]
	}

	// Compute the zero values for padding
	zeros := emptyTreeRoots()

	currentLevel := make([][32]byte, len(leaves))
	copy(currentLevel, leaves)

	for level := 0; level < TreeDepth; level++ {
		// Pad to even length
		if len(currentLevel)%2 != 0 {
			currentLevel = append(currentLevel, zeros[level])
		}

		nextLevel := make([][32]byte, len(currentLevel)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			nextLevel[i/2] = computeNodeHash(currentLevel[i], currentLevel[i+1])
		}
		currentLevel = nextLevel
	}

	return currentLevel[0]
}

// emptyTreeRoots computes the precomputed zero values for each tree level.
// These match LicenseRegistry.sol's constructor.
func emptyTreeRoots() [TreeDepth + 1][32]byte {
	var zeros [TreeDepth + 1][32]byte

	// zeros[0] = keccak256(0)
	zeroUint256 := make([]byte, 32) // 256 bits of zero
	zeros[0] = crypto.Keccak256Hash(zeroUint256)

	for i := 1; i <= TreeDepth; i++ {
		zeros[i] = computeNodeHash(zeros[i-1], zeros[i-1])
	}

	return zeros
}

// computeNodeHash computes keccak256(left || right) — the internal node hash
// used in LicenseRegistry.sol's Merkle tree.
func computeNodeHash(left, right [32]byte) [32]byte {
	var combined []byte
	combined = append(combined, left[:]...)
	combined = append(combined, right[:]...)
	return [32]byte(crypto.Keccak256Hash(combined))
}

// ComputeAuditLeaf computes a leaf hash for the audit anchor Merkle tree.
func ComputeAuditLeaf(entryHash [32]byte) [32]byte {
	return [32]byte(crypto.Keccak256(entryHash[:]))
}

// BlockToBytes converts a block number to a 32-byte big-endian representation.
func BlockToBytes(blockNum uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], blockNum)
	return b
}

// HashToBytes converts a common.Hash to a byte slice.
func HashToBytes(h common.Hash) []byte {
	b := make([]byte, 32)
	copy(b, h[:])
	return b
}
