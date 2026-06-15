// Package server exposes the shyware transfer layer over HTTP.
// It is a stateless proxy: every handler calls api/rpc.Client to query CometBFT ABCI
// state or broadcast transactions; no local state is kept.
//
// Privacy contract: GET /transfers/{id} returns only asset_id and transfer_id — never
// amount, sender, or recipient. Account commitments are hashed; wallet addresses are
// never stored or returned.
//
// Operator-only endpoints (POST /mint, POST /burn) require the caller to have already
// constructed and signed the Tx; this server forwards them without inspection.
package server

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/ShywareLLC/community/shywire/api/rpc"
)

// Server is a stateless HTTP proxy to the shyware CometBFT node.
type Server struct {
	rpc         *rpc.Client
	serviceName string
}

func NewServer(cometbftRPC, serviceName string) *Server {
	return &Server{rpc: rpc.NewClient(cometbftRPC), serviceName: serviceName}
}

// Router returns an http.Handler. Callers may wrap with deployment-specific middleware
// (e.g. operator auth for mint/burn, rate limiting, Tor-aware headers).
func (s *Server) Router() http.Handler {
	r := mux.NewRouter()

	r.Use(corsMiddleware)

	// Public read-only endpoints.
	r.HandleFunc("/health", s.health).Methods("GET")
	r.HandleFunc("/assets/{asset_id}", s.getAsset).Methods("GET")
	r.HandleFunc("/supply/{asset_id}", s.getSupply).Methods("GET")
	r.HandleFunc("/balance/{asset_id}/{account_commitment}", s.getBalance).Methods("GET")
	r.HandleFunc("/transfers/{transfer_id}", s.getTransfer).Methods("GET")
	r.HandleFunc("/contracts/{contract_id}", s.getContract).Methods("GET")
	r.HandleFunc("/contracts/executions/{execution_id}", s.getContractExecution).Methods("GET")
	r.HandleFunc("/custody/policies", s.listCustodyPolicies).Methods("GET")
	r.HandleFunc("/custody/policies/current", s.getCurrentCustodyPolicy).Methods("GET")
	r.HandleFunc("/custody/policies/{policy_id}", s.getCustodyPolicy).Methods("GET")
	r.HandleFunc("/custody/operators", s.listCustodyOperators).Methods("GET")
	r.HandleFunc("/custody/operators/{operator_id}", s.getCustodyOperator).Methods("GET")
	r.HandleFunc("/custody/skus", s.listCustodySkuClasses).Methods("GET")
	r.HandleFunc("/custody/skus/{sku_class_id}", s.getCustodySkuClass).Methods("GET")
	r.HandleFunc("/custody/lots", s.listCustodyLots).Methods("GET")
	r.HandleFunc("/custody/lots/{lot_id}", s.getCustodyLot).Methods("GET")
	r.HandleFunc("/custody/redemptions", s.listCustodyRedemptions).Methods("GET")
	r.HandleFunc("/custody/redemptions/{request_id}", s.getCustodyRedemption).Methods("GET")
	r.HandleFunc("/custody/settlements", s.listCustodySettlements).Methods("GET")
	r.HandleFunc("/custody/settlements/{settlement_id}", s.getCustodySettlement).Methods("GET")
	r.HandleFunc("/custody/demurrage", s.listCustodyDemurrage).Methods("GET")
	r.HandleFunc("/custody/demurrage/{assessment_id}", s.getCustodyDemurrage).Methods("GET")

	// Account registration — any authenticated user (wallet proof in Tx body).
	r.HandleFunc("/accounts", s.registerAccount).Methods("POST")

	// Transfer submission — requires valid nullifier + sender proof in Tx body.
	r.HandleFunc("/assets", s.registerAsset).Methods("POST")
	r.HandleFunc("/transfers", s.submitTransfer).Methods("POST")
	r.HandleFunc("/contracts", s.registerContract).Methods("POST")
	r.HandleFunc("/contracts/activate", s.activateContract).Methods("POST")
	r.HandleFunc("/contracts/executions", s.submitContractExecution).Methods("POST")
	r.HandleFunc("/custody/policies", s.registerCustodyPolicy).Methods("POST")
	r.HandleFunc("/custody/operators", s.registerCustodyOperator).Methods("POST")
	r.HandleFunc("/custody/skus", s.registerCustodySkuClass).Methods("POST")
	r.HandleFunc("/custody/lots", s.recordCustodyLot).Methods("POST")
	r.HandleFunc("/custody/redemptions", s.requestCustodyRedemption).Methods("POST")
	r.HandleFunc("/custody/redemptions/settle", s.settleCustodyRedemption).Methods("POST")
	r.HandleFunc("/custody/demurrage", s.applyCustodyDemurrage).Methods("POST")

	// Operator-only — mint and burn require operator signature in Tx body.
	r.HandleFunc("/mint", s.mint).Methods("POST")
	r.HandleFunc("/burn", s.burn).Methods("POST")

	return r
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	status, err := s.rpc.Status()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "node unreachable")
		return
	}
	writeJSON(w, status)
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	assetID := mux.Vars(r)["asset_id"]
	data, err := s.rpc.ABCIQuery("/asset/" + assetID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getSupply(w http.ResponseWriter, r *http.Request) {
	assetID := mux.Vars(r)["asset_id"]
	data, err := s.rpc.ABCIQuery("/supply/" + assetID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

// getBalance looks up an account balance by asset_id and account_commitment.
// The account_commitment is H(wallet_address) — wallet address is never stored.
func (s *Server) getBalance(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	assetID := vars["asset_id"]
	commitment := vars["account_commitment"]
	data, err := s.rpc.ABCIQuery("/balance/" + assetID + "/" + commitment)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

// getTransfer returns a TransferRecord (List 1): asset_id, transfer_id, timestamp.
// Amount is NOT returned — privacy guardrail.
func (s *Server) getTransfer(w http.ResponseWriter, r *http.Request) {
	transferID := mux.Vars(r)["transfer_id"]
	data, err := s.rpc.ABCIQuery("/transfer/" + transferID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getContract(w http.ResponseWriter, r *http.Request) {
	contractID := mux.Vars(r)["contract_id"]
	data, err := s.rpc.ABCIQuery("/contract/" + contractID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getContractExecution(w http.ResponseWriter, r *http.Request) {
	executionID := mux.Vars(r)["execution_id"]
	data, err := s.rpc.ABCIQuery("/contract/execution/" + executionID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) listCustodyPolicies(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/policies")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getCurrentCustodyPolicy(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/policies/current")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getCustodyPolicy(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/policies/" + mux.Vars(r)["policy_id"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) listCustodyOperators(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/operators")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getCustodyOperator(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/operators/" + mux.Vars(r)["operator_id"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) listCustodySkuClasses(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/skus")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getCustodySkuClass(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/skus/" + mux.Vars(r)["sku_class_id"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) listCustodyLots(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/lots")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getCustodyLot(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/lots/" + mux.Vars(r)["lot_id"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) listCustodyRedemptions(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/redemptions")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getCustodyRedemption(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/redemptions/" + mux.Vars(r)["request_id"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) listCustodySettlements(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/settlements")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getCustodySettlement(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/settlements/" + mux.Vars(r)["settlement_id"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) listCustodyDemurrage(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/demurrage")
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) getCustodyDemurrage(w http.ResponseWriter, r *http.Request) {
	data, err := s.rpc.ABCIQuery("/custody/demurrage/" + mux.Vars(r)["assessment_id"])
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, data)
}

func (s *Server) registerAccount(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) registerAsset(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) submitTransfer(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) registerContract(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) activateContract(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) submitContractExecution(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) registerCustodyPolicy(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) registerCustodyOperator(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) registerCustodySkuClass(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) recordCustodyLot(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) requestCustodyRedemption(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) settleCustodyRedemption(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) applyCustodyDemurrage(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) mint(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

func (s *Server) burn(w http.ResponseWriter, r *http.Request) {
	s.broadcastTx(w, r)
}

// broadcastTx decodes a {"tx": "<base64-encoded-tx>"} body and broadcasts it.
func (s *Server) broadcastTx(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tx string `json:"tx"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Tx == "" {
		writeError(w, http.StatusBadRequest, "missing tx field")
		return
	}
	result, err := s.rpc.BroadcastTx([]byte(body.Tx))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, result)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
