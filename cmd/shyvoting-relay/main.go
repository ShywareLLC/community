package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/ShywareLLC/community/api/relay"
)

func main() {
	upstream := flag.String("upstream", "http://127.0.0.1:8080", "Canonical shyvoting API base URL")
	port := flag.String("port", "8081", "HTTP listen port")
	flag.Parse()

	srv := relay.NewServer(*upstream)
	addr := ":" + *port
	log.Printf("shyvoting-relay listening on %s (upstream: %s)", addr, *upstream)
	if err := http.ListenAndServe(addr, srv.Router()); err != nil {
		log.Fatalf("shyvoting-relay: %v", err)
	}
}
