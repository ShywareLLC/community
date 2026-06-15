package main

// Lambda entry point for shyvoting API deployments.
//
// Build: GOOS=linux GOARCH=arm64 go build -o bootstrap ./cmd/shyvoting-api-lambda/
// Deploy: zip bootstrap.zip bootstrap && aws lambda update-function-code ...

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/akrylysov/algnhsa"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/ShywareLLC/community/api/server"
	"github.com/ShywareLLC/community/services/reconcile"
	"github.com/ShywareLLC/community/shyvoting/middleware"
)

var lambdaRouter http.Handler

func init() {
	ctx := context.Background()

	serviceName := os.Getenv("SERVICE_NAME")
	if serviceName == "" {
		serviceName = "shyvoting-api"
	}

	srv := server.NewServer(mustEnv("COMETBFT_RPC"), serviceName)

	if crdbURL := os.Getenv("CRDB_URL"); crdbURL != "" {
		db, err := sql.Open("pgx", crdbURL)
		if err != nil {
			log.Fatalf("shyvoting-api-lambda: open CockroachDB: %v", err)
		}
		if err := db.PingContext(ctx); err != nil {
			log.Fatalf("shyvoting-api-lambda: ping CockroachDB: %v", err)
		}
		srv.WithReconcileStore(reconcile.NewCRDBStore(db))
	}

	router := srv.Router()

	if credPath := os.Getenv("FIREBASE_CREDENTIALS_PATH"); credPath != "" {
		fa, err := middleware.NewFirebaseAuth(ctx, credPath)
		if err != nil {
			log.Fatalf("shyvoting-api-lambda: init Firebase auth: %v", err)
		}
		router = fa.OnWrites(router)
	}

	lambdaRouter = router
}

func main() {
	algnhsa.ListenAndServe(lambdaRouter, nil)
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "required env var %s is not set\n", key)
		os.Exit(1)
	}
	return v
}
