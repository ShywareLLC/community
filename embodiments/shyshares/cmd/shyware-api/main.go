// shyware-api starts the shyshares HTTP API server.
//
// Usage:
//
//	shyware-api --port 8081
//
// In production, wire a CockroachDB-backed store instead of the in-memory one.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ShywareLLC/community/shyshares/api"
)

func main() {
	port := flag.String("port", "8081", "HTTP server port")
	flag.Parse()

	store := api.NewStore()
	srv := &http.Server{
		Addr:         ":" + *port,
		Handler:      api.Router(store),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		fmt.Printf("shyware-api started on :%s\n", *port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
