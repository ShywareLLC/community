package types

import (
	"encoding/json"
	"fmt"
	"time"
)

// Block represents a CometBFT block with its results.
type Block struct {
	Height          int64
	ChainID         string
	Time            time.Time
	ProposerAddress string
	NumTxs          int
	TotalGas        int64
	Txs             [][]byte
	TxResults       []*TxResult
}

// TxResult represents a transaction result.
type TxResult struct {
	TxHash    string
	Index     int
	TxType    string
	GasWanted int64
	GasUsed   int64
	Success   bool
	Log       string
	Events    []*Event
}

// Event represents an ABCI event.
type Event struct {
	Type       string
	Attributes []*EventAttribute
}

// EventAttribute represents an event attribute.
type EventAttribute struct {
	Key   string
	Value string
	Index bool
}

// ParseBlock parses block data and block results from CometBFT RPC responses.
func ParseBlock(blockData, resultsData []byte) (*Block, error) {
	var blockResp struct {
		Result struct {
			Block struct {
				Header struct {
					Height          string    `json:"height"`
					ChainID         string    `json:"chain_id"`
					Time            time.Time `json:"time"`
					ProposerAddress string    `json:"proposer_address"`
				} `json:"header"`
				Data struct {
					Txs []string `json:"txs"`
				} `json:"data"`
			} `json:"block"`
		} `json:"result"`
	}

	if err := json.Unmarshal(blockData, &blockResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal block: %w", err)
	}

	var resultsResp struct {
		Result struct {
			Height     string `json:"height"`
			TxsResults []struct {
				Code      int    `json:"code"`
				Data      string `json:"data"`
				Log       string `json:"log"`
				GasWanted string `json:"gas_wanted"`
				GasUsed   string `json:"gas_used"`
				Events    []struct {
					Type       string `json:"type"`
					Attributes []struct {
						Key   string `json:"key"`
						Value string `json:"value"`
						Index bool   `json:"index"`
					} `json:"attributes"`
				} `json:"events"`
			} `json:"txs_results"`
		} `json:"result"`
	}

	if err := json.Unmarshal(resultsData, &resultsResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal results: %w", err)
	}

	var height int64
	fmt.Sscanf(blockResp.Result.Block.Header.Height, "%d", &height)

	block := &Block{
		Height:          height,
		ChainID:         blockResp.Result.Block.Header.ChainID,
		Time:            blockResp.Result.Block.Header.Time,
		ProposerAddress: blockResp.Result.Block.Header.ProposerAddress,
		NumTxs:          len(blockResp.Result.Block.Data.Txs),
		Txs:             make([][]byte, 0),
		TxResults:       make([]*TxResult, 0),
	}

	for i, txRes := range resultsResp.Result.TxsResults {
		var gasWanted, gasUsed int64
		fmt.Sscanf(txRes.GasWanted, "%d", &gasWanted)
		fmt.Sscanf(txRes.GasUsed, "%d", &gasUsed)

		block.TotalGas += gasUsed

		txResult := &TxResult{
			TxHash:    fmt.Sprintf("tx_%d_%d", height, i),
			Index:     i,
			TxType:    "unknown",
			GasWanted: gasWanted,
			GasUsed:   gasUsed,
			Success:   txRes.Code == 0,
			Log:       txRes.Log,
			Events:    make([]*Event, 0),
		}

		for _, ev := range txRes.Events {
			event := &Event{
				Type:       ev.Type,
				Attributes: make([]*EventAttribute, 0),
			}

			for _, attr := range ev.Attributes {
				event.Attributes = append(event.Attributes, &EventAttribute{
					Key:   attr.Key,
					Value: attr.Value,
					Index: attr.Index,
				})

				if ev.Type == "poll_created" || ev.Type == "submission_accepted" || ev.Type == "poll_closed" || ev.Type == "confirmation_processed" {
					txResult.TxType = ev.Type
				}
			}

			txResult.Events = append(txResult.Events, event)
		}

		block.TxResults = append(block.TxResults, txResult)
	}

	return block, nil
}
