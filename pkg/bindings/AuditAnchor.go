package bindings

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const auditAnchorABI = `[
	{"type":"function","name":"anchorBatch","inputs":[{"name":"batchId","type":"uint256"},{"name":"merkleRoot","type":"bytes32"}],"outputs":[],"stateMutability":"nonpayable"},
	{"type":"function","name":"batchRoots","inputs":[{"name":"","type":"uint256"}],"outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},
	{"type":"function","name":"batchTimestamp","inputs":[{"name":"","type":"uint256"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
	{"type":"function","name":"latestBatchId","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
	{"type":"function","name":"verifyBatchLeaf","inputs":[{"name":"batchId","type":"uint256"},{"name":"leaf","type":"bytes32"},{"name":"proof","type":"bytes32[]"},{"name":"leafIndex","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
	{"type":"event","name":"BatchAnchored","inputs":[{"name":"batchId","type":"uint256","indexed":true},{"name":"merkleRoot","type":"bytes32","indexed":false},{"name":"timestamp","type":"uint256","indexed":false}],"anonymous":false}
]`

// AuditAnchor provides type-safe access to AuditAnchor.sol.
type AuditAnchor struct {
	ABI  abi.ABI
	Addr common.Address
}

// NewAuditAnchor creates a binding for the given contract address.
func NewAuditAnchor(addr common.Address) (*AuditAnchor, error) {
	parsed, err := abi.JSON(strings.NewReader(auditAnchorABI))
	if err != nil {
		return nil, err
	}
	return &AuditAnchor{ABI: parsed, Addr: addr}, nil
}

// PackAnchorBatch encodes calldata for anchorBatch(uint256,bytes32).
func (c *AuditAnchor) PackAnchorBatch(batchId *big.Int, merkleRoot [32]byte) ([]byte, error) {
	return c.ABI.Pack("anchorBatch", batchId, merkleRoot)
}

// PackVerifyBatchLeaf encodes calldata for verifyBatchLeaf(uint256,bytes32,bytes32[],uint256).
func (c *AuditAnchor) PackVerifyBatchLeaf(batchId *big.Int, leaf [32]byte, proof [][32]byte, leafIndex *big.Int) ([]byte, error) {
	return c.ABI.Pack("verifyBatchLeaf", batchId, leaf, proof, leafIndex)
}

// UnpackLatestBatchId decodes the return value of latestBatchId().
func (c *AuditAnchor) UnpackLatestBatchId(data []byte) (*big.Int, error) {
	out, err := c.ABI.Unpack("latestBatchId", data)
	if err != nil {
		return nil, err
	}
	return *abi.ConvertType(out[0], new(*big.Int)).(**big.Int), nil
}

// UnpackBatchRoots decodes the return value of batchRoots(uint256).
func (c *AuditAnchor) UnpackBatchRoots(data []byte) ([32]byte, error) {
	out, err := c.ABI.Unpack("batchRoots", data)
	if err != nil {
		return [32]byte{}, err
	}
	return *abi.ConvertType(out[0], new([32]byte)).(*[32]byte), nil
}

// BatchAnchoredEvent is the parsed BatchAnchored event from AuditAnchor.sol.
type BatchAnchoredEvent struct {
	BatchId    *big.Int `json:"batch_id"`
	MerkleRoot [32]byte `json:"merkle_root"`
	Timestamp  *big.Int `json:"timestamp"`
	Raw        types.Log
}

// BatchAnchoredEventSig is the keccak256 of "BatchAnchored(uint256,bytes32,uint256)".
var BatchAnchoredEventSig = crypto.Keccak256Hash([]byte("BatchAnchored(uint256,bytes32,uint256)"))

// ParseBatchAnchoredEvent decodes a raw log into a BatchAnchoredEvent.
func (c *AuditAnchor) ParseBatchAnchoredEvent(log types.Log) (*BatchAnchoredEvent, error) {
	event := new(BatchAnchoredEvent)
	if err := c.ABI.UnpackIntoInterface(event, "BatchAnchored", log.Data); err != nil {
		return nil, err
	}
	event.Raw = log
	if len(log.Topics) >= 2 {
		event.BatchId = new(big.Int).SetBytes(log.Topics[1].Bytes())
	}
	return event, nil
}
