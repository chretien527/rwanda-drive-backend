package chain

import "fmt"

// ChainError represents a blockchain-related error.
type ChainError struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e ChainError) Error() string {
	return e.Message
}

var (
	ErrNotConnected       = ChainError{"failed to connect to blockchain RPC", "CHAIN_NOT_CONNECTED"}
	ErrContractNotDeployed = ChainError{"contract not deployed at specified address", "CHAIN_CONTRACT_NOT_DEPLOYED"}
	ErrTransactionFailed  = ChainError{"transaction failed", "CHAIN_TX_FAILED"}
	ErrAlreadyIssued      = ChainError{"license already issued", "CHAIN_ALREADY_ISSUED"}
	ErrNotIssuer          = ChainError{"signer is not the platform signer", "CHAIN_NOT_ISSUER"}
	ErrTreeFull           = ChainError{"Merkle tree is full", "CHAIN_TREE_FULL"}
	ErrEventParseFailed   = ChainError{"failed to parse contract event", "CHAIN_EVENT_PARSE_FAILED"}
	ErrSyncFailed         = ChainError{"failed to sync chain events", "CHAIN_SYNC_FAILED"}
)

func WrapTxError(err error, txHash string) error {
	return fmt.Errorf("transaction %s failed: %w", txHash, err)
}
