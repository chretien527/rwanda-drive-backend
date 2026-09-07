package chain

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/0xEmmyb2/CipherPass/pkg/bindings"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"go.mongodb.org/mongo-driver/bson"
)

// EventListener polls for contract events and keeps Postgres in sync with on-chain state.
type EventListener struct {
	service *Service
	logger  config.LoggerInterface
	stopCh  chan struct{}
}

// NewEventListener creates a new event listener.
func NewEventListener(service *Service, logger config.LoggerInterface) *EventListener {
	return &EventListener{
		service: service,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
}

// Start begins the event polling loop in a background goroutine.
func (l *EventListener) Start(ctx context.Context) {
	go l.pollLoop(ctx)
	l.logger.Info("Chain event listener started")
}

// Stop signals the listener to shut down gracefully.
func (l *EventListener) Stop() {
	close(l.stopCh)
	l.logger.Info("Chain event listener stopped")
}

// pollLoop periodically checks for new events from all tracked contracts.
func (l *EventListener) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(l.service.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		case <-ticker.C:
			if err := l.pollLicenseRegistry(ctx); err != nil {
				l.logger.WithError(err).Error("Failed to poll LicenseRegistry events")
			}
		}
	}
}

// pollLicenseRegistry fetches new LicenseIssued events since the last synced block.
func (l *EventListener) pollLicenseRegistry(ctx context.Context) error {
	lastBlock, err := l.service.GetLastSyncedBlock(ctx, "LicenseRegistry")
	if err != nil {
		return fmt.Errorf("failed to get last synced block: %w", err)
	}

	// Build filter query for LicenseIssued events
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(lastBlock + 1),
		ToBlock:   nil, // latest
		Addresses: []common.Address{l.service.cfg.LicenseRegistry},
		Topics:    [][]common.Hash{{bindings.LicenseIssuedEventSig}},
	}

	logs, err := l.service.client.FilterLogs(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to filter logs: %w", err)
	}

	for _, vLog := range logs {
		if err := l.handleLicenseIssued(ctx, vLog); err != nil {
			l.logger.WithError(err).WithField("tx_hash", vLog.TxHash.Hex()).Error("Failed to handle LicenseIssued event")
			continue
		}
	}

	// Update sync cursor
	if len(logs) > 0 {
		lastLog := logs[len(logs)-1]
		if err := l.service.UpdateSyncedBlock(ctx, "LicenseRegistry", int64(lastLog.BlockNumber)); err != nil {
			l.logger.WithError(err).Error("Failed to update sync cursor")
		}
	}

	return nil
}

// handleLicenseIssued processes a single LicenseIssued event:
// 1. Parses the event
// 2. Looks up the matching Postgres record
// 3. Updates leaf_index, on_chain_root, and synced_at
func (l *EventListener) handleLicenseIssued(ctx context.Context, vLog types.Log) error {
	event, err := l.service.license.ParseLicenseIssuedEvent(vLog)
	if err != nil {
		return fmt.Errorf("failed to parse LicenseIssued event: %w", err)
	}

	l.logger.WithFields(map[string]interface{}{
		"leaf_hash":  common.BytesToHash(event.LeafHash[:]).Hex(),
		"leaf_index": event.LeafIndex.String(),
		"new_root":   common.BytesToHash(event.NewRoot[:]).Hex(),
		"block":      vLog.BlockNumber,
	}).Info("LicenseIssued event received")

	// Update the database record with on-chain confirmation
	now := time.Now()
	res, err := l.service.db.Collection("license_leaves").UpdateOne(ctx,
		bson.M{"keccak256_leaf": event.LeafHash[:], "synced_at": nil},
		bson.M{"$set": bson.M{"leaf_index": event.LeafIndex.Int64(), "on_chain_root": event.NewRoot[:], "synced_at": now}},
	)
	if err != nil {
		return fmt.Errorf("failed to update license leaf: %w", err)
	}

	if res.MatchedCount == 0 {
		l.logger.WithField("leaf_hash", common.BytesToHash(event.LeafHash[:]).Hex()).
			Warn("No matching record for LicenseIssued event")
	}

	return nil
}

// SyncToBlock performs a one-shot sync up to a specific block number.
func (l *EventListener) SyncToBlock(ctx context.Context, targetBlock uint64) error {
	currentBlock, err := l.service.client.BlockNumber(ctx)
	if err != nil {
		return err
	}

	if targetBlock > currentBlock {
		targetBlock = currentBlock
	}

	l.logger.WithFields(map[string]interface{}{
		"target": targetBlock,
		"latest": currentBlock,
	}).Info("Syncing chain events to target block")

	lastSynced, _ := l.service.GetLastSyncedBlock(ctx, "LicenseRegistry")
	chunkSize := uint64(1000)

	for from := uint64(lastSynced + 1); from <= targetBlock; from += chunkSize {
		to := from + chunkSize - 1
		if to > targetBlock {
			to = targetBlock
		}

		query := ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(from),
			ToBlock:   new(big.Int).SetUint64(to),
			Addresses: []common.Address{l.service.cfg.LicenseRegistry},
			Topics:    [][]common.Hash{{bindings.LicenseIssuedEventSig}},
		}

		logs, err := l.service.client.FilterLogs(ctx, query)
		if err != nil {
			return err
		}

		for _, vLog := range logs {
			if err := l.handleLicenseIssued(ctx, vLog); err != nil {
				l.logger.WithError(err).Error("Failed to handle event during sync")
			}
		}

		if len(logs) > 0 {
			lastLog := logs[len(logs)-1]
			l.service.UpdateSyncedBlock(ctx, "LicenseRegistry", int64(lastLog.BlockNumber))
		}
	}

	l.logger.Info("Chain event sync complete")
	return nil
}
