//go:build js && wasm

// Command zk-prover-wasm compiles to a WASM binary that exposes the
// shyware NullifierCircuit prover to browser JavaScript via three globals:
//
//   shywareZKComputeCommitment(personSecret)
//     → { ok: true, value: "<commitmentHex>" }
//     → { ok: false, error: "..." }
//
//   shywareZKComputeNullifier(personSecret, pollId)
//     → { ok: true, value: "<nullifierHex>" }
//
//   shywareZKProve(personSecret, pollId, provingKeyBase64)
//     → { ok: true, value: { proof: "<base64>", commitment: "<hex>", nullifier: "<hex>" } }
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -o zk-prover.wasm ./cmd/zk-prover-wasm
//
// Browser usage (requires wasm_exec.js from the Go distribution):
//
//	<script src="/static/wasm_exec.js"></script>
//	<script>
//	  const go = new Go()
//	  WebAssembly.instantiateStreaming(fetch("/static/zk-prover.wasm"), go.importObject)
//	    .then(r => go.run(r.instance))
//	</script>
//
// Then call shywareZKProve() etc. from zkpClient.js after the WASM is ready.
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"syscall/js"

	"github.com/ShywareLLC/community/protocol/zkp"
)

func main() {
	js.Global().Set("shywareZKComputeCommitment", js.FuncOf(computeCommitment))
	js.Global().Set("shywareZKComputeNullifier", js.FuncOf(computeNullifier))
	js.Global().Set("shywareZKProve", js.FuncOf(prove))

	// Signal readiness — zkpClient.js polls this flag before calling provers.
	js.Global().Set("shywareZKReady", js.ValueOf(true))

	// Block forever — the WASM must stay alive for the page lifetime.
	select {}
}

func computeCommitment(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errResult("missing personSecret argument")
	}
	commitment, err := zkp.ComputeCommitment(args[0].String())
	if err != nil {
		return errResult(fmt.Sprintf("ComputeCommitment: %v", err))
	}
	return okResult(js.ValueOf(commitment))
}

func computeNullifier(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return errResult("expected (personSecret, pollId)")
	}
	nullifier, err := zkp.ComputeNullifier(args[0].String(), args[1].String())
	if err != nil {
		return errResult(fmt.Sprintf("ComputeNullifier: %v", err))
	}
	return okResult(js.ValueOf(nullifier))
}

func prove(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return errResult("expected (personSecret, pollId, provingKeyBase64)")
	}
	personSecret := args[0].String()
	pollID := args[1].String()
	pkBase64 := args[2].String()

	pkBytes, err := base64.StdEncoding.DecodeString(pkBase64)
	if err != nil {
		return errResult(fmt.Sprintf("invalid proving key base64: %v", err))
	}

	prover, err := zkp.NewProver(bytes.NewReader(pkBytes))
	if err != nil {
		return errResult(fmt.Sprintf("load proving key: %v", err))
	}

	proofBytes, commitmentHex, nullifierHex, err := prover.Prove(personSecret, pollID)
	if err != nil {
		return errResult(fmt.Sprintf("prove: %v", err))
	}

	result := map[string]any{
		"proof":      base64.StdEncoding.EncodeToString(proofBytes),
		"commitment": commitmentHex,
		"nullifier":  nullifierHex,
	}
	return okResult(js.ValueOf(result))
}

func okResult(value js.Value) map[string]any {
	return map[string]any{"ok": true, "value": value}
}

func errResult(msg string) map[string]any {
	return map[string]any{"ok": false, "error": msg}
}
