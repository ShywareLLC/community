// shyware-abci is the unified ABCI binary for all shyshares-v1 deployments.
//
// It reads a shyconfig.json manifest and starts a CometBFT ABCI socket server
// for the combined shyvoting + shywire state machine. No deployment-specific
// Go code is required — the manifest drives everything.
//
// Usage:
//
//	shyware-abci \
//	  --config   /path/to/shyconfig.json \
//	  --db-path  /opt/shyware/data \
//	  --addr     tcp://0.0.0.0:26658 \
//	  --log-level info
//
// Secret/REDACTED values in the shyconfig can be supplied via env vars instead
// of the config file (see config.applyEnvOverrides for names).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	abciserver "github.com/cometbft/cometbft/abci/server"
	"github.com/cometbft/cometbft/libs/log"

	shyconfig "github.com/ShywareLLC/community/protocol/config"
	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/services/telemetry"

	sharesapp "github.com/ShywareLLC/community/shyshares/app"
)

func main() {
	configPath := flag.String("config", "shyconfig.json", "Path to shyconfig.json")
	abciAddr   := flag.String("addr", "tcp://0.0.0.0:26658", "ABCI server address")
	dbPath     := flag.String("db-path", "/opt/shyware/data", "Root directory for state databases")
	logLevel   := flag.String("log-level", "info", "Log level (debug|info|warn|error)")
	flag.Parse()

	base := log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	allowLevel, err := log.AllowLevel(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level: %v\n", err)
		os.Exit(1)
	}
	logger := log.NewFilter(base, allowLevel)

	manifest, err := shyconfig.Load(*configPath)
	if err != nil {
		logger.Error("Failed to load shyconfig", "path", *configPath, "error", err)
		os.Exit(1)
	}

	verifier, err := buildVerifier(manifest, logger)
	if err != nil {
		logger.Error("Failed to build identity verifier", "error", err)
		os.Exit(1)
	}

	authorityKeys, err := decodeKeySlice(manifest.Governance.AuthorityKeys, "governance.authority_keys")
	if err != nil {
		logger.Error("Invalid authority_keys", "error", err)
		os.Exit(1)
	}
	houseKeys, err := decodeKeySlice(manifest.Governance.HouseKeys, "governance.house_keys")
	if err != nil {
		logger.Error("Invalid house_keys", "error", err)
		os.Exit(1)
	}

	appName := manifest.App.Name
	if appName == "" {
		appName = manifest.App.ID
	}

	ctx := context.Background()

	_, otelShutdown, err := telemetry.Init(ctx, "shyware-abci")
	if err != nil {
		logger.Error("Failed to initialise telemetry", "error", err)
	}
	defer func() {
		if otelShutdown != nil {
			if err := otelShutdown(ctx); err != nil {
				logger.Error("OTel shutdown error", "error", err)
			}
		}
	}()

	application, err := sharesapp.New(ctx, sharesapp.Config{
		ChainID: manifest.App.ChainID,
		AppName: appName,

		VotingDBPath:   filepath.Join(*dbPath, "voting"),
		VotingDBName:   manifest.App.ID + "-voting",
		VotingKMSKeyID: manifest.Signing.TallyKeyID,
		Verifier:       verifier,

		WireDBPath: filepath.Join(*dbPath, "wire"),
		WireDBName: manifest.App.ID + "-wire",

		GovAssetID:     manifest.Governance.Eligibility.AssetID,
		MinVoteBalance: manifest.Governance.Eligibility.MinBalance,

		AuthorityKeys: authorityKeys,
		HouseKeys:     houseKeys,
	}, logger)
	if err != nil {
		logger.Error("Failed to create shyware application", "error", err)
		os.Exit(1)
	}

	server := abciserver.NewSocketServer(*abciAddr, application)
	server.SetLogger(logger)
	if err := server.Start(); err != nil {
		logger.Error("Failed to start ABCI server", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			logger.Error("Error stopping ABCI server", "error", err)
		}
	}()

	logger.Info("shyware-abci started",
		"config", *configPath,
		"addr", *abciAddr,
		"chain_id", manifest.App.ChainID,
		"identity_provider", manifest.Identity.Provider,
		"gov_asset_id", manifest.Governance.Eligibility.AssetID,
		"authority_keys", len(authorityKeys),
		"house_keys", len(houseKeys),
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	logger.Info("Shutting down shyware-abci...")
}

func buildVerifier(m *shyconfig.Manifest, logger log.Logger) (identity.IdentityVerifier, error) {
	switch m.Identity.Provider {
	case "didit":
		pub, err := decodeEd25519Key(m.Identity.IssuerPubKeyHex, "identity.issuer_pubkey_hex")
		if err != nil {
			return nil, err
		}
		logger.Info("Identity provider: didit")
		return &identity.DiditVerifier{PubKey: pub}, nil

	case "identus":
		pub, err := decodeEd25519Key(m.Identity.IssuerPubKeyHex, "identity.issuer_pubkey_hex")
		if err != nil {
			return nil, err
		}
		logger.Info("Identity provider: identus")
		return &identity.IdentusVerifier{IssuerPubKey: pub}, nil

	case "wallet":
		logger.Info("Identity provider: wallet (EVM address commitment)")
		return &identity.WalletVerifier{}, nil

	case "none":
		logger.Info("Identity provider: none (dev/demo only)")
		return &identity.NoopVerifier{}, nil

	default:
		return nil, fmt.Errorf("unsupported identity.provider %q in shyconfig", m.Identity.Provider)
	}
}

func decodeKeySlice(hexes []string, field string) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(hexes))
	for i, h := range hexes {
		k, err := decodeEd25519Key(h, fmt.Sprintf("%s[%d]", field, i))
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func decodeEd25519Key(hexStr, field string) (ed25519.PublicKey, error) {
	hexStr = strings.TrimSpace(hexStr)
	if hexStr == "" || strings.HasPrefix(hexStr, "REDACTED") {
		return nil, fmt.Errorf("%s is required (set in shyconfig or SHYWARE_IDENTITY_ISSUER_PUBKEY_HEX env)", field)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid hex: %w", field, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s must be %d bytes (Ed25519), got %d", field, ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}
