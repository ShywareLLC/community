// Command zk-setup performs a single-party Groth16 trusted setup for the
// shyware NullifierCircuit, writing nullifier_pk.bin (proving key) and
// nullifier_vk.bin (verifying key) to the current directory.
//
// WARNING: This is a SINGLE-PARTY setup — suitable for development and testing
// only. For production, replace with an MPC ceremony (e.g. Hermez/snarkjs
// phase2 over the R1CS produced here).
//
// Usage:
//
//	go run ./cmd/zk-setup
//
// Outputs:
//
//	nullifier_pk.bin  — proving key; distribute to clients for proof generation
//	nullifier_vk.bin  — verifying key; load into ABCI via --zk-vk-path
//
// After setup, start the ABCI with:
//
//	populist-abci --zk-vk-path ./nullifier_vk.bin ...
package main

import (
	"fmt"
	"os"

	"github.com/ShywareLLC/community/protocol/zkp"
	"github.com/consensys/gnark/backend/groth16"
)

func main() {
	fmt.Println("shyware zk-setup: compiling NullifierCircuit to R1CS...")
	cs, err := zkp.Compile()
	if err != nil {
		fatal("compile circuit", err)
	}
	fmt.Printf("  constraints: %d\n", cs.GetNbConstraints())

	fmt.Println("shyware zk-setup: running Groth16 trusted setup (single-party)...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fatal("groth16 setup", err)
	}

	pkFile, err := os.Create("nullifier_pk.bin")
	if err != nil {
		fatal("create nullifier_pk.bin", err)
	}
	if _, err := pk.WriteTo(pkFile); err != nil {
		pkFile.Close()
		fatal("write proving key", err)
	}
	pkFile.Close()
	fmt.Println("  wrote nullifier_pk.bin  (proving key — distribute to clients)")

	vkFile, err := os.Create("nullifier_vk.bin")
	if err != nil {
		fatal("create nullifier_vk.bin", err)
	}
	if _, err := vk.WriteTo(vkFile); err != nil {
		vkFile.Close()
		fatal("write verifying key", err)
	}
	vkFile.Close()
	fmt.Println("  wrote nullifier_vk.bin  (verifying key — load with --zk-vk-path)")

	fmt.Println("shyware zk-setup: done.")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Start the ABCI: populist-abci --zk-vk-path ./nullifier_vk.bin ...")
	fmt.Println("  2. Serve nullifier_pk.bin at a path the browser SDK can fetch.")
	fmt.Println("  3. For production: run a Groth16 MPC ceremony over the R1CS instead.")
}

func fatal(context string, err error) {
	fmt.Fprintf(os.Stderr, "zk-setup: %s: %v\n", context, err)
	os.Exit(1)
}
