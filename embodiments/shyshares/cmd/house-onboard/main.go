// house-onboard verifies a Persona KYB inquiry for a house (warehouse/vault
// owner) entity and binds the entity to an Ed25519 signing key.
//
// Usage:
//
//	house-onboard \
//	  --inquiry-id <persona-inquiry-id> \
//	  --pub-key-hex <ed25519-hex> \
//	  --webhook-secret <persona-webhook-secret> \
//	  --sig-header <Persona-Signature header value> \
//	  --payload-file <path to raw webhook body>
//
// On success, prints the EntityRecord as JSON and exits 0.
// Add the printed pub_key_hex to governance.house_keys in shyconfig.json.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ShywareLLC/community/services/identity"
)

func main() {
	inquiryID     := flag.String("inquiry-id", "", "Persona inquiry ID")
	pubKeyHex     := flag.String("pub-key-hex", "", "Hex-encoded Ed25519 public key to bind to the verified entity")
	webhookSecret := flag.String("webhook-secret", "", "Persona webhook signing secret")
	sigHeader     := flag.String("sig-header", "", "Value of the Persona-Signature header")
	payloadFile   := flag.String("payload-file", "", "Path to the raw Persona webhook event body")
	flag.Parse()

	if *pubKeyHex == "" || *webhookSecret == "" || *sigHeader == "" || *payloadFile == "" {
		fmt.Fprintln(os.Stderr, "usage: house-onboard --pub-key-hex <hex> --webhook-secret <secret> --sig-header <sig> --payload-file <file>")
		os.Exit(1)
	}

	payload, err := os.ReadFile(*payloadFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read payload file: %v\n", err)
		os.Exit(1)
	}

	v := &identity.PersonaVerifier{WebhookSecret: *webhookSecret}
	record, err := v.VerifyEntity(&identity.EntityVerificationRequest{
		InquiryID:       *inquiryID,
		EntityPubKeyHex: *pubKeyHex,
		WebhookSig:      *sigHeader,
		WebhookPayload:  payload,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "KYB verification failed: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(record, "", "  ")
	fmt.Println(string(out))
	fmt.Fprintln(os.Stderr, "Entity approved. Add pub_key_hex to governance.house_keys in shyconfig.json.")
}
