package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/populist/analytics/config"
	"github.com/populist/analytics/indexer"
	"github.com/populist/analytics/projector"
	"github.com/populist/analytics/server"
	"github.com/populist/analytics/subscriber"
)

func main() {
	configPath := flag.String("config", "config/config.yaml", "Path to configuration file")
	httpAddr   := flag.String("http-addr", "", "HTTP listen address for analytics query API (empty = disabled)")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	pool, err := pgxpool.New(ctx, cfg.PostgreSQL.URL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to PostgreSQL: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to ping PostgreSQL: %v\n", err)
		os.Exit(1)
	}

	proj := projector.New(pool)
	sub  := subscriber.New(cfg.CometBFT.RPC, proj)
	idx  := indexer.New(sub, proj, pool)

	if err := idx.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start indexer: %v\n", err)
		os.Exit(1)
	}

	if *httpAddr != "" {
		srv := server.New(pool)
		go func() {
			if err := http.ListenAndServe(*httpAddr, srv.Handler()); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "Analytics API error: %v\n", err)
			}
		}()
		fmt.Printf("   Analytics API: %s\n", *httpAddr)
	}

	fmt.Println("shyvoting-affinities started")
	fmt.Printf("   CometBFT RPC: %s\n", cfg.CometBFT.RPC)
	fmt.Printf("   PostgreSQL:   %s\n", cfg.PostgreSQL.Host)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("Shutting down...")
	idx.Stop()
}

func loadConfig(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}
