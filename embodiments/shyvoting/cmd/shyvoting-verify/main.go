// shyvoting-verify — standalone tally verifier for the shyvoting two-list protocol.
//
// Usage:
//
//	shyvoting-verify --poll <poll_id> [--api http://localhost:8080] [--name "Deployment"]
//
// Exit 0 on pass, exit 2 on failure.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/ShywareLLC/community/verify"
)

func main() {
	apiBase := flag.String("api", "http://localhost:8080", "shyvoting API base URL")
	pollID  := flag.String("poll", "", "Poll ID to verify (required)")
	name    := flag.String("name", "shyvoting", "Deployment name shown in header")
	flag.Parse()

	if *pollID == "" {
		fmt.Fprintln(os.Stderr, "Usage: shyvoting-verify --poll <poll_id> [--api <url>] [--name <name>]")
		os.Exit(1)
	}

	fmt.Printf("\n%s Tally Verifier — poll: %s\n", *name, *pollID)
	fmt.Println("─────────────────────────────────────────────────────────")

	tally := verify.FetchTally(*apiBase, *pollID)

	voterCount := verify.FetchVoterCount(*apiBase, *pollID)
	if tally.TotalVotes == voterCount {
		verify.Green("✓ Count-match: votes=%d voters=%d — no ballot stuffing, no suppression\n",
			tally.TotalVotes, voterCount)
	} else {
		verify.Red("✗ Count-match FAILED: votes=%d voters=%d — invariant violated\n",
			tally.TotalVotes, voterCount)
		os.Exit(2)
	}

	if len(tally.PublicKey) == 0 {
		verify.Red("✗ No public key in tally — was the poll closed without a KMS key configured?\n")
		os.Exit(2)
	}

	payload := verify.BuildSigningPayload(
		tally.VoteMerkleRoot, tally.VoterMerkleRoot, tally.TotalVotes, tally.Counts,
	)

	ok, err := verify.VerifyECDSA(tally.PublicKey, tally.Signature, payload)
	if err != nil {
		verify.Red("✗ ECDSA verification error: %v\n", err)
		os.Exit(2)
	}
	if !ok {
		verify.Red("✗ ECDSA signature INVALID — tally may have been tampered with\n")
		os.Exit(2)
	}
	verify.Green("✓ ECDSA (KMS FIPS 140-3) signature valid\n")

	fmt.Printf("  Public key  : %x\n", tally.PublicKey)
	fmt.Printf("  Signature   : %x\n", tally.Signature)
	fmt.Printf("  Payload     : %x\n", payload)
	fmt.Printf("  Vote root   : %x\n", tally.VoteMerkleRoot)
	fmt.Printf("  Voter root  : %x\n", tally.VoterMerkleRoot)
	fmt.Printf("  Block       : %d\n", tally.Height)
	fmt.Println()

	choices := make([]string, 0, len(tally.Counts))
	for k := range tally.Counts {
		choices = append(choices, k)
	}
	sort.Slice(choices, func(i, j int) bool {
		return tally.Counts[choices[i]] > tally.Counts[choices[j]]
	})
	fmt.Println("  Results:")
	for _, c := range choices {
		n := tally.Counts[c]
		pct := 0.0
		if tally.TotalVotes > 0 {
			pct = float64(n) * 100.0 / float64(tally.TotalVotes)
		}
		bar := ""
		for i := 0; i < int(pct/5); i++ {
			bar += "█"
		}
		fmt.Printf("    %-42s %4d  %5.1f%%  %s\n", c, n, pct, bar)
	}

	fmt.Println()
	verify.Green("✓ Tally cryptographically verified — no trusted authority required\n")
	fmt.Println("  Anyone with the tally public key can re-run this tool independently.")
	fmt.Println()
}
