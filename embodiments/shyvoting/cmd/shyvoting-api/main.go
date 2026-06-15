package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"net/http"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/ShywareLLC/community/api/server"
	"github.com/ShywareLLC/community/services/reconcile"
	"github.com/ShywareLLC/community/shyvoting/middleware"
)

func main() {
	cometbftRPC   := flag.String("cometbft-rpc", "http://127.0.0.1:26657", "CometBFT RPC endpoint")
	port          := flag.String("port", "8080", "HTTP listen port")
	serviceName   := flag.String("service-name", "shyvoting-api", "OTel service name")
	crdbURL       := flag.String("crdb-url", os.Getenv("CRDB_URL"), "CockroachDB URL (empty = write-only posture)")
	firebaseCreds := flag.String("firebase-creds", os.Getenv("FIREBASE_CREDENTIALS_PATH"), "Firebase credentials path (empty = no auth)")
	flag.Parse()

	ctx := context.Background()

	srv := server.NewServer(*cometbftRPC, *serviceName)

	if *crdbURL != "" {
		db, err := sql.Open("pgx", *crdbURL)
		if err != nil {
			log.Fatalf("shyvoting-api: open CockroachDB: %v", err)
		}
		defer db.Close()
		if err := db.PingContext(ctx); err != nil {
			log.Fatalf("shyvoting-api: ping CockroachDB: %v", err)
		}
		srv.WithReconcileStore(reconcile.NewCRDBStore(db))
		log.Print("shyvoting-api: reconciling authority configured")
	}

	router := srv.Router()

	if *firebaseCreds != "" {
		fa, err := middleware.NewFirebaseAuth(ctx, *firebaseCreds)
		if err != nil {
			log.Fatalf("shyvoting-api: init Firebase auth: %v", err)
		}
		router = fa.OnWrites(router)
		log.Print("shyvoting-api: Firebase auth enabled on writes")
	}

	addr := ":" + *port
	log.Printf("shyvoting-api listening on %s (cometbft: %s)", addr, *cometbftRPC)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("shyvoting-api: %v", err)
	}
}
