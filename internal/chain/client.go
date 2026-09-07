package chain

import (
	"context"
	"fmt"
	"math/big"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Client wraps an Ethereum RPC client with convenience methods.
type Client struct {
	rpc     *ethclient.Client
	signer  Signer
	chainID *big.Int
	cfg     config.ChainConfig
}

// NewClient creates a new chain client.
func NewClient(cfg config.ChainConfig, signer Signer) (*Client, error) {
	rpc, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC at %s: %w", cfg.RPCURL, err)
	}

	// Verify connection
	chainID, err := rpc.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	return &Client{
		rpc:     rpc,
		signer:  signer,
		chainID: chainID,
		cfg:     cfg,
	}, nil
}

// RPC returns the underlying ethclient for direct use.
func (c *Client) RPC() *ethclient.Client {
	return c.rpc
}

// ChainID returns the connected chain's ID.
func (c *Client) ChainID() *big.Int {
	return c.chainID
}

// SignerAddress returns the platform signer's Ethereum address.
func (c *Client) SignerAddress() common.Address {
	return c.signer.Address()
}

// SendSignedTransaction signs and sends a transaction.
func (c *Client) SendSignedTransaction(ctx context.Context, tx *types.Transaction) (*types.Transaction, error) {
	signedTx, err := c.signer.SignTransaction(ctx, c.chainID, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	err = c.rpc.SendTransaction(ctx, signedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}

	return signedTx, nil
}

// CallContract performs a read-only (eth_call) contract call.
func (c *Client) CallContract(ctx context.Context, msg ethereum.CallMsg) ([]byte, error) {
	return c.rpc.CallContract(ctx, msg, nil)
}

// PendingNonce returns the pending transaction count for the signer's address.
func (c *Client) PendingNonce(ctx context.Context) (uint64, error) {
	return c.rpc.PendingNonceAt(ctx, c.signer.Address())
}

// SuggestGasPrice suggests a gas price for legacy transactions.
func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return c.rpc.SuggestGasPrice(ctx)
}

// BlockNumber returns the latest block number.
func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	return c.rpc.BlockNumber(ctx)
}

// HeaderByNumber returns the block header for the given number.
func (c *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	return c.rpc.HeaderByNumber(ctx, number)
}

// FilterLogs returns logs matching the given query.
func (c *Client) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	return c.rpc.FilterLogs(ctx, q)
}

// WatchFilterLogs subscribes to log events matching the given query.
func (c *Client) WatchFilterLogs(ctx context.Context, q ethereum.FilterQuery) (chan types.Log, ethereum.Subscription, error) {
	ch := make(chan types.Log)
	sub, err := c.rpc.SubscribeFilterLogs(ctx, q, ch)
	if err != nil {
		return nil, nil, err
	}
	return ch, sub, nil
}

// BuildContractCall creates an ethereum.CallMsg for a read-only contract call.
func (c *Client) BuildContractCall(to common.Address, data []byte) ethereum.CallMsg {
	return ethereum.CallMsg{
		From: c.signer.Address(),
		To:   &to,
		Data: data,
	}
}

// --- Validation helper ---

// ValidateAddress checks if an address is non-zero.
func ValidateAddress(addr common.Address) bool {
	return addr != (common.Address{})
}

// RequireValidAddress panics if the address is the zero address.
func RequireValidAddress(addr common.Address, name string) {
	if !ValidateAddress(addr) {
		panic(fmt.Sprintf("contract address %s is not configured (zero address)", name))
	}
}

