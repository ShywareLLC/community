package subscriber

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ShywareLLC/community/analytics/types"
)

// Projector processes blocks from the subscriber.
type Projector interface {
	ProcessBlock(ctx context.Context, block *types.Block) error
}

// Subscriber polls CometBFT RPC for new blocks and forwards them to a Projector.
type Subscriber struct {
	rpcURL    string
	projector Projector
}

// New creates a new Subscriber.
func New(rpcURL string, projector Projector) *Subscriber {
	return &Subscriber{rpcURL: rpcURL, projector: projector}
}

// Start begins polling for new blocks. It returns immediately; polling runs in a goroutine.
func (s *Subscriber) Start(ctx context.Context) error {
	currentHeight, err := s.getLatestHeight(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest height: %w", err)
	}

	fmt.Printf("📦 Starting from block height %d\n", currentHeight)

	ticker := time.NewTicker(1 * time.Second)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				newHeight, err := s.getLatestHeight(ctx)
				if err != nil {
					fmt.Printf("⚠️  Error getting latest height: %v\n", err)
					continue
				}
				for h := currentHeight + 1; h <= newHeight; h++ {
					if err := s.processBlockAtHeight(ctx, h); err != nil {
						fmt.Printf("⚠️  Error processing block %d: %v\n", h, err)
						continue
					}
					currentHeight = h
				}
			}
		}
	}()

	return nil
}

func (s *Subscriber) getLatestHeight(ctx context.Context) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.rpcURL+"/status", nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Result struct {
			SyncInfo struct {
				LatestBlockHeight string `json:"latest_block_height"`
			} `json:"sync_info"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	var height int64
	fmt.Sscanf(result.Result.SyncInfo.LatestBlockHeight, "%d", &height)
	return height, nil
}

func (s *Subscriber) processBlockAtHeight(ctx context.Context, height int64) error {
	block, err := s.fetchBlock(ctx, height)
	if err != nil {
		return fmt.Errorf("failed to fetch block: %w", err)
	}
	if err := s.projector.ProcessBlock(ctx, block); err != nil {
		return fmt.Errorf("failed to process block: %w", err)
	}
	fmt.Printf("✅ Processed block %d (%d txs)\n", height, len(block.Txs))
	return nil
}

func (s *Subscriber) fetchBlock(ctx context.Context, height int64) (*types.Block, error) {
	blockData, err := s.get(ctx, fmt.Sprintf("%s/block?height=%d", s.rpcURL, height))
	if err != nil {
		return nil, err
	}
	resultsData, err := s.get(ctx, fmt.Sprintf("%s/block_results?height=%d", s.rpcURL, height))
	if err != nil {
		return nil, err
	}
	block, err := types.ParseBlock(blockData, resultsData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}
	return block, nil
}

func (s *Subscriber) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
