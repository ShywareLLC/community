package middleware

import (
	"context"
	"net/http"
	"strings"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

// FirebaseAuth provides Firebase JWT verification for POST routes.
// GET routes (polls, votes, voters, tally) remain public; only ballot
// submission, update, and confirm require a valid Firebase ID token.
type FirebaseAuth struct {
	authClient *auth.Client
}

// NewFirebaseAuth creates a FirebaseAuth from a service-account credentials file.
func NewFirebaseAuth(ctx context.Context, credentialsPath string) (*FirebaseAuth, error) {
	app, err := firebase.NewApp(ctx, nil, option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return nil, err
	}
	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, err
	}
	return &FirebaseAuth{authClient: authClient}, nil
}

// Verify wraps next, requiring a valid Bearer token in the Authorization header.
func (fa *FirebaseAuth) Verify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
			return
		}
		decoded, err := fa.authClient.VerifyIDToken(r.Context(), token)
		if err != nil {
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "userID", decoded.UID)
		if email, ok := decoded.Claims["email"].(string); ok {
			ctx = context.WithValue(ctx, "email", email)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OnWrites wraps next, applying fa.Verify only to POST requests.
// GETs (polls, votes, voters, tally) remain public.
func (fa *FirebaseAuth) OnWrites(next http.Handler) http.Handler {
	authed := fa.Verify(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			authed.ServeHTTP(w, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
