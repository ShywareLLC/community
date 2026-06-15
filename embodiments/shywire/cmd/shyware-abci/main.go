package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	abciserver "github.com/cometbft/cometbft/abci/server"
	"github.com/cometbft/cometbft/libs/log"

	apiserver "github.com/ShywareLLC/community/shywire/api/server"
	"github.com/ShywareLLC/community/shywire/app"
)

func main() {
	var (
		abciAddr = flag.String("addr", "tcp://0.0.0.0:26658", "ABCI server address")
		httpAddr = flag.String("http-addr", "0.0.0.0:8080", "HTTP API server address")
		cometRPC = flag.String("comet-rpc", "http://127.0.0.1:26657", "CometBFT RPC address for HTTP API")
		chainID  = flag.String("chain-id", "shyware-1", "Chain ID")
		dbPath   = flag.String("db-path", "/opt/shyware/data", "State database path")
		dbName   = flag.String("db-name", "shyware", "State database name")
		appName  = flag.String("app-name", "shyware", "Application name (used in HTTP server span names)")
		logLevel = flag.String("log-level", "info", "Log level (debug|info|warn|error)")
	)
	flag.Parse()

	base := log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	allowLevel, err := log.AllowLevel(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level: %v\n", err)
		os.Exit(1)
	}
	logger := log.NewFilter(base, allowLevel)

	ctx := context.Background()

	cfg := app.Config{
		ChainID: *chainID,
		DBPath:  *dbPath,
		DBName:  *dbName,
		AppName: *appName,
	}

	application, err := app.New(ctx, cfg, logger)
	if err != nil {
		logger.Error("Failed to create shyware application", "error", err)
		os.Exit(1)
	}

	// Start ABCI socket server.
	abci := abciserver.NewSocketServer(*abciAddr, application)
	abci.SetLogger(logger)
	if err := abci.Start(); err != nil {
		logger.Error("Failed to start ABCI server", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := abci.Stop(); err != nil {
			logger.Error("Error stopping ABCI server", "error", err)
		}
	}()

	// Start HTTP API server.
	httpSrv := apiserver.NewServer(*cometRPC, *appName)
	go func() {
		logger.Info("HTTP API server listening", "addr", *httpAddr)
		if err := http.ListenAndServe(*httpAddr, httpSrv.Router()); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	logger.Info("shyware started",
		"abci_addr", *abciAddr,
		"http_addr", *httpAddr,
		"chain_id", *chainID,
		"db_path", *dbPath,
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	logger.Info("Shutting down shyware...")
}
