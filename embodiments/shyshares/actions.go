package shyshares

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// NewQueuedAction creates the canonical queued governance action for a
// passed proposal. The action ID is derived from the proposal ID so it
// is deterministic and idempotent across retries.
func NewQueuedAction(proposal GovernanceProposal) QueuedGovernanceAction {
	actionID := fmt.Sprintf("act-%s", proposal.ID)
	if len(proposal.QueuedActionIDs) > 0 {
		actionID = proposal.QueuedActionIDs[0]
	}
	return QueuedGovernanceAction{
		ID:             actionID,
		OrganizationID: proposal.OrganizationID,
		ProposalID:     proposal.ID,
		ActionType:     proposal.ProposalClass,
		Adapter:        proposal.ExecutionAdapter,
		Status:         "queued",
		Payload:        proposal.Payload,
		CreatedAt:      time.Now().UTC(),
	}
}

// BuildActionDispatch constructs the dispatch record for a queued action.
// Adapter endpoints are resolved from environment variables so deployment
// binaries configure them without modifying SDK code:
//
//	SHYSHARES_SHYWIRE_BASE_URL — base URL for the shywire canonical queue
//	SHYSHARES_BYODAO_TARGET    — target identifier for BYODAO adapter
func BuildActionDispatch(action QueuedGovernanceAction, dispatchedBy string) map[string]any {
	dispatch := map[string]any{
		"adapter":       action.Adapter,
		"dispatched_by": dispatchedBy,
		"status":        "submitted",
	}

	switch action.Adapter {
	case AdapterShywire:
		dispatch["status"] = "queued_for_shywire"
		dispatch["canonical_queue"] = true
		dispatch["rail"] = AdapterShywire
		if endpoint := strings.TrimSpace(os.Getenv("SHYSHARES_SHYWIRE_BASE_URL")); endpoint != "" {
			dispatch["adapter_endpoint"] = endpoint
		}
	case AdapterByodao:
		dispatch["status"] = "queued_for_byodao"
		dispatch["canonical_queue"] = true
		if target := strings.TrimSpace(os.Getenv("SHYSHARES_BYODAO_TARGET")); target != "" {
			dispatch["adapter_target"] = target
		}
	default:
		dispatch["status"] = "internal_applied"
		dispatch["canonical_queue"] = true
	}

	return dispatch
}
