// zk-setup performs the one-time Groth16 trusted setup for the shyvoting
// NullifierCircuit and writes the proving key (pk) and verifying key (vk)
// to disk.
//
// Usage:
//
//	go run ./cmd/zk-setup [-pk nullifier_pk.bin] [-vk nullifier_vk.bin] [-name shyvoting]
//
// Outputs:
//
//	nullifier_pk.bin — proving key (distribute to clients / kept by operators)
//	nullifier_vk.bin — verifying key (loaded by every ABCI node on startup)
//
// WARNING: This performs a single-party trusted setup. For production, replace
// with a Groth16 MPC ceremony (Phase 2 over a universal SRS such as
// Hermez Perpetual Powers of Tau).
//
// After running:
//  1. Copy nullifier_vk.bin to /opt/<deployment>/nullifier_vk.bin on each validator.
//  2. Start shyvoting-abci with --zk-vk-path /opt/<deployment>/nullifier_vk.bin.
//  3. Embed nullifier_pk.bin in iOS/Android/web client builds.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"

	"github.com/ShywareLLC/community/protocol/zkp"
)

func main() {
	pkPath := flag.String("pk", "nullifier_pk.bin", "Path to write proving key")
	vkPath := flag.String("vk", "nullifier_vk.bin", "Path to write verifying key")
	name   := flag.String("name", "shyvoting", "Deployment name (used in output messages)")
	flag.Parse()

	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Printf("  %s — ZK Nullifier Trusted Setup\n", *name)
	fmt.Println("  Circuit: NullifierCircuit (MiMC over BN254)")
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println()

	fmt.Print("Compiling NullifierCircuit to R1CS ... ")
	cs, err := zkp.Compile()
	if err != nil {
		log.Fatalf("compile: %v", err)
	}
	fmt.Printf("done.\n")
	fmt.Printf("  Constraints: %d\n", cs.GetNbConstraints())
	fmt.Printf("  Curve: BN254\n")
	fmt.Println()

	fmt.Print("Running Groth16 trusted setup ... ")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		log.Fatalf("setup: %v", err)
	}
	fmt.Println("done.")
	fmt.Println()

	pkFile, err := os.Create(*pkPath)
	if err != nil {
		log.Fatalf("create pk file: %v", err)
	}
	n, err := pk.WriteTo(pkFile)
	pkFile.Close()
	if err != nil {
		log.Fatalf("write pk: %v", err)
	}
	fmt.Printf("  Proving key : %s (%d bytes)\n", *pkPath, n)

	vkFile, err := os.Create(*vkPath)
	if err != nil {
		log.Fatalf("create vk file: %v", err)
	}
	m, err := vk.WriteTo(vkFile)
	vkFile.Close()
	if err != nil {
		log.Fatalf("write vk: %v", err)
	}
	fmt.Printf("  Verifying key: %s (%d bytes)\n", *vkPath, m)

	// Smoke-test: verify the VK can be read back.
	vkCheck := groth16.NewVerifyingKey(ecc.BN254)
	f, _ := os.Open(*vkPath)
	if _, err := vkCheck.ReadFrom(f); err != nil {
		log.Fatalf("readback vk check: %v", err)
	}
	f.Close()

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("  Next steps:")
	fmt.Println()
	fmt.Printf("  1. Copy %s to each validator:\n", *vkPath)
	fmt.Printf("       scp %s validator:/opt/%s/\n", *vkPath, *name)
	fmt.Println()
	fmt.Printf("  2. Start ABCI with VK path:\n")
	fmt.Printf("       shyvoting-abci --zk-vk-path /opt/%s/%s\n", *name, *vkPath)
	fmt.Println()
	fmt.Printf("  3. Embed %s in iOS/Android/web client builds.\n", *pkPath)
	fmt.Println()
	fmt.Println("  ⚠  PRODUCTION: Replace single-party setup with an MPC ceremony.")
	fmt.Printf("     Constraint count to submit to coordinator: %d\n", cs.GetNbConstraints())
	fmt.Println("══════════════════════════════════════════════════════════")
}
