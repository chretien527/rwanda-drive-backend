// Package bindings provides Go bindings for Ikizere smart contracts.
// These are hand-written equivalents of abigen-generated code.
// To regenerate: abigen --sol ../contracts/src/LicenseRegistry.sol --pkg bindings --out LicenseRegistry.go
package bindings

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const licenseRegistryABI = `[
	{"type":"function","name":"getRoot","inputs":[],"outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},
	{"type":"function","name":"isIssued","inputs":[{"name":"","type":"bytes32"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
	{"type":"function","name":"nextLeafIndex","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
	{"type":"function","name":"leafIndexOf","inputs":[{"name":"","type":"bytes32"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
	{"type":"function","name":"TREE_DEPTH","inputs":[],"outputs":[{"name":"","type":"uint8"}],"stateMutability":"view"},
	{"type":"function","name":"issueLicense","inputs":[{"name":"leafHash","type":"bytes32"}],"outputs":[{"name":"leafIndex","type":"uint256"}],"stateMutability":"nonpayable"},
	{"type":"function","name":"verifyInclusion","inputs":[{"name":"leafHash","type":"bytes32"},{"name":"proofSiblings","type":"bytes32[20]"},{"name":"leafIndex","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
	{"type":"event","name":"LicenseIssued","inputs":[{"name":"leafHash","type":"bytes32","indexed":true},{"name":"leafIndex","type":"uint256","indexed":true},{"name":"newRoot","type":"bytes32","indexed":false}],"anonymous":false}
]`

// LicenseRegistry is a type-safe wrapper for interacting with LicenseRegistry.sol.
type LicenseRegistry struct {
	ABI  abi.ABI
	Addr common.Address
}

// NewLicenseRegistry creates a binding for the given contract address.
func NewLicenseRegistry(addr common.Address) (*LicenseRegistry, error) {
	parsed, err := abi.JSON(strings.NewReader(licenseRegistryABI))
	if err != nil {
		return nil, err
	}
	return &LicenseRegistry{ABI: parsed, Addr: addr}, nil
}

// --- Pack helpers (build calldata for state-changing calls) ---

// PackIssueLicense encodes calldata for issueLicense(bytes32).
func (c *LicenseRegistry) PackIssueLicense(leafHash [32]byte) ([]byte, error) {
	return c.ABI.Pack("issueLicense", leafHash)
}

// --- Unpack helpers (decode return data from eth_call) ---

// UnpackGetRoot decodes the return value of getRoot().
func (c *LicenseRegistry) UnpackGetRoot(data []byte) (common.Hash, error) {
	out, err := c.ABI.Unpack("getRoot", data)
	if err != nil {
		return common.Hash{}, err
	}
	return *abi.ConvertType(out[0], new([32]byte)).(*[32]byte), nil
}

// UnpackIsIssued decodes the return value of isIssued(bytes32).
func (c *LicenseRegistry) UnpackIsIssued(data []byte) (bool, error) {
	out, err := c.ABI.Unpack("isIssued", data)
	if err != nil {
		return false, err
	}
	return *abi.ConvertType(out[0], new(bool)).(*bool), nil
}

// UnpackNextLeafIndex decodes the return value of nextLeafIndex().
func (c *LicenseRegistry) UnpackNextLeafIndex(data []byte) (*big.Int, error) {
	out, err := c.ABI.Unpack("nextLeafIndex", data)
	if err != nil {
		return nil, err
	}
	return *abi.ConvertType(out[0], new(*big.Int)).(**big.Int), nil
}

// UnpackIssueLicense decodes the return value of issueLicense(bytes32).
func (c *LicenseRegistry) UnpackIssueLicense(data []byte) (*big.Int, error) {
	out, err := c.ABI.Unpack("issueLicense", data)
	if err != nil {
		return nil, err
	}
	return *abi.ConvertType(out[0], new(*big.Int)).(**big.Int), nil
}

// --- Event parsing ---

// LicenseIssuedEvent is the parsed LicenseIssued event from LicenseRegistry.sol.
type LicenseIssuedEvent struct {
	LeafHash  [32]byte `json:"leaf_hash"`
	LeafIndex *big.Int `json:"leaf_index"`
	NewRoot   [32]byte `json:"new_root"`
	Raw       types.Log
}

// LicenseIssuedEventSig is the keccak256 of "LicenseIssued(bytes32,uint256,bytes32)".
var LicenseIssuedEventSig = crypto.Keccak256Hash([]byte("LicenseIssued(bytes32,uint256,bytes32)"))

// ParseLicenseIssuedEvent decodes a raw log into a LicenseIssuedEvent.
// Indexed parameters are extracted from Topics; non-indexed from Data.
func (c *LicenseRegistry) ParseLicenseIssuedEvent(log types.Log) (*LicenseIssuedEvent, error) {
	event := new(LicenseIssuedEvent)
	if err := c.ABI.UnpackIntoInterface(event, "LicenseIssued", log.Data); err != nil {
		return nil, err
	}
	event.Raw = log

	// Topics[0] = event signature, Topics[1] = leafHash (indexed), Topics[2] = leafIndex (indexed)
	if len(log.Topics) >= 3 {
		copy(event.LeafHash[:], log.Topics[1].Bytes())
		event.LeafIndex = new(big.Int).SetBytes(log.Topics[2].Bytes())
	}
	return event, nil
}
