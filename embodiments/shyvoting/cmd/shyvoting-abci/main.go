package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	abciserver "github.com/cometbft/cometbft/abci/server"
	"github.com/cometbft/cometbft/libs/log"

	protocolapp "github.com/ShywareLLC/community/app"
	"github.com/ShywareLLC/community/services/identity"
	"github.com/ShywareLLC/community/services/telemetry"
	"github.com/ShywareLLC/community/protocol/zkp"
)

func main() {
	var (
		abciAddr     = flag.String("addr", "tcp://0.0.0.0:26658", "ABCI server address")
		chainID      = flag.String("chain-id", "shyvoting-1", "CometBFT chain ID")
		dbPath       = flag.String("db-path", "/opt/shyvoting/data", "State database path")
		dbName       = flag.String("db-name", "shyvoting", "State database name")
		appName      = flag.String("app-name", "Shyvoting Protocol", "Application display name")
		tracerName   = flag.String("tracer-name", "shyvoting-abci", "OTel tracer service name")
		kmsKeyID     = flag.String("kms-key-id", "", "AWS KMS key ID for HSM-backed tally attestation")
		logLevel     = flag.String("log-level", "info", "Log level (debug|info|warn|error)")
		identityMode = flag.String("identity-mode", "didit", "IDV mode: didit | zk | identus | wallet")
		diditPubKey  = flag.String("didit-pubkey", "", "Hex-encoded Ed25519 Didit public key (didit and zk modes)")
		zkVKPath     = flag.String("zk-vk-path", "", "Path to Groth16 verifying key (zk mode)")
		identusPubKey = flag.String("identus-issuer-pubkey", "", "Hex-encoded Ed25519 Identus issuer public key (identus mode)")
	)
	flag.Parse()

	base := log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	allowLevel, err := log.AllowLevel(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level: %v\n", err)
		os.Exit(1)
	}
	logger := log.NewFilter(base, allowLevel)

	verifier, err := buildVerifier(*identityMode, *diditPubKey, *zkVKPath, *identusPubKey, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identity verifier init failed: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	_, otelShutdown, err := telemetry.Init(ctx, *tracerName)
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

	application, err := protocolapp.New(ctx, protocolapp.Config{
		ChainID:    *chainID,
		DBPath:     *dbPath,
		DBName:     *dbName,
		AppName:    *appName,
		TracerName: *tracerName,
		KMSKeyID:   *kmsKeyID,
		Verifier:   verifier,
	}, logger)
	if err != nil {
		logger.Error("Failed to create application", "error", err)
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

	logger.Info("shyvoting-abci started",
		"addr", *abciAddr,
		"chain_id", *chainID,
		"db_name", *dbName,
		"identity_mode", *identityMode,
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	logger.Info("Shutting down shyvoting-abci...")
}

func buildVerifier(mode, diditPubKeyHex, zkVKPath, identusPubKeyHex string, logger log.Logger) (identity.IdentityVerifier, error) {
	switch mode {
	case "didit":
		pub, err := decodeEd25519Key(diditPubKeyHex, "--didit-pubkey")
		if err != nil {
			return nil, err
		}
		logger.Info("Identity mode: didit", "pubkey_prefix", diditPubKeyHex[:8]+"...")
		return &identity.DiditVerifier{PubKey: pub}, nil

	case "zk":
		pub, err := decodeEd25519Key(diditPubKeyHex, "--didit-pubkey")
		if err != nil {
			return nil, err
		}
		if zkVKPath == "" {
			return nil, fmt.Errorf("--zk-vk-path is required for zk identity mode")
		}
		f, err := os.Open(zkVKPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open ZK verifying key at %s: %w", zkVKPath, err)
		}
		zkv, err := zkp.NewVerifier(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to load ZK verifying key: %w", err)
		}
		logger.Info("Identity mode: zk", "vk_path", zkVKPath)
		return &identity.ZKVerifier{DiditPubKey: pub, ZK: zkv}, nil

	case "identus":
		pub, err := decodeEd25519Key(identusPubKeyHex, "--identus-issuer-pubkey")
		if err != nil {
			return nil, err
		}
		logger.Info("Identity mode: identus", "pubkey_prefix", identusPubKeyHex[:8]+"...")
		return &identity.IdentusVerifier{IssuerPubKey: pub}, nil

	case "wallet":
		logger.Info("Identity mode: wallet (EVM address commitment)")
		return &identity.WalletVerifier{}, nil

	default:
		return nil, fmt.Errorf("unknown --identity-mode %q: must be didit | zk | identus | wallet", mode)
	}
}

func decodeEd25519Key(hexStr, flagName string) (ed25519.PublicKey, error) {
	if hexStr == "" {
		return nil, fmt.Errorf("%s is required for this identity mode", flagName)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid hex: %w", flagName, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s must decode to %d bytes (Ed25519), got %d", flagName, ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}
