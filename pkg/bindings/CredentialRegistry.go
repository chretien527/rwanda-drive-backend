package bindings

import (
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const credentialRegistryABI = `[
	{"type":"function","name":"checkStatus","inputs":[{"name":"credentialHash","type":"bytes32"}],"outputs":[{"name":"","type":"uint8"}],"stateMutability":"view"},
	{"type":"function","name":"isActive","inputs":[{"name":"credentialHash","type":"bytes32"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
	{"type":"function","name":"setStatus","inputs":[{"name":"credentialHash","type":"bytes32"},{"name":"newStatus","type":"uint8"}],"outputs":[],"stateMutability":"nonpayable"},
	{"type":"function","name":"lastUpdated","inputs":[{"name":"","type":"bytes32"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
	{"type":"event","name":"StatusChanged","inputs":[{"name":"credentialHash","type":"bytes32","indexed":true},{"name":"oldStatus","type":"uint8","indexed":false},{"name":"newStatus","type":"uint8","indexed":false},{"name":"timestamp","type":"uint256","indexed":false}],"anonymous":false}
]`

// On-chain credential statuses (mirrors CredentialRegistry.Status enum)
const (
	CredentialNone     uint8 = 0
	CredentialActive   uint8 = 1
	CredentialRevoked  uint8 = 2
	CredentialSuspended uint8 = 3
)

// CredentialRegistry provides type-safe access to CredentialRegistry.sol.
type CredentialRegistry struct {
	ABI  abi.ABI
	Addr common.Address
}

// NewCredentialRegistry creates a binding for the given contract address.
func NewCredentialRegistry(addr common.Address) (*CredentialRegistry, error) {
	parsed, err := abi.JSON(strings.NewReader(credentialRegistryABI))
	if err != nil {
		return nil, err
	}
	return &CredentialRegistry{ABI: parsed, Addr: addr}, nil
}

// PackSetStatus encodes calldata for setStatus(bytes32,uint8).
func (c *CredentialRegistry) PackSetStatus(credentialHash [32]byte, newStatus uint8) ([]byte, error) {
	return c.ABI.Pack("setStatus", credentialHash, newStatus)
}

// PackCheckStatus encodes calldata for checkStatus(bytes32).
func (c *CredentialRegistry) PackCheckStatus(credentialHash [32]byte) ([]byte, error) {
	return c.ABI.Pack("checkStatus", credentialHash)
}

// PackIsActive encodes calldata for isActive(bytes32).
func (c *CredentialRegistry) PackIsActive(credentialHash [32]byte) ([]byte, error) {
	return c.ABI.Pack("isActive", credentialHash)
}

// UnpackCheckStatus decodes the return value of checkStatus(bytes32).
func (c *CredentialRegistry) UnpackCheckStatus(data []byte) (uint8, error) {
	out, err := c.ABI.Unpack("checkStatus", data)
	if err != nil {
		return 0, err
	}
	return *abi.ConvertType(out[0], new(uint8)).(*uint8), nil
}

// UnpackIsActive decodes the return value of isActive(bytes32).
func (c *CredentialRegistry) UnpackIsActive(data []byte) (bool, error) {
	out, err := c.ABI.Unpack("isActive", data)
	if err != nil {
		return false, err
	}
	return *abi.ConvertType(out[0], new(bool)).(*bool), nil
}

// StatusChangedEvent is the parsed StatusChanged event from CredentialRegistry.sol.
type StatusChangedEvent struct {
	CredentialHash [32]byte `json:"credential_hash"`
	OldStatus      uint8    `json:"old_status"`
	NewStatus      uint8    `json:"new_status"`
	Timestamp      uint64   `json:"timestamp"`
	Raw            types.Log
}

// ParseStatusChangedEvent decodes a raw log into a StatusChangedEvent.
func (c *CredentialRegistry) ParseStatusChangedEvent(log types.Log) (*StatusChangedEvent, error) {
	event := new(StatusChangedEvent)
	if err := c.ABI.UnpackIntoInterface(event, "StatusChanged", log.Data); err != nil {
		return nil, err
	}
	event.Raw = log
	if len(log.Topics) >= 2 {
		copy(event.CredentialHash[:], log.Topics[1].Bytes())
	}
	return event, nil
}
