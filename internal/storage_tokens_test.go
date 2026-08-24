package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pfisterer/cloud-self-service-golib/token"
)

// An expired token must not authenticate. The lazy cleanup in List only runs
// when the owner lists their tokens, so the expiry has to be enforced on the
// lookup path itself.
func TestExpiredTokenDoesNotAuthenticate(t *testing.T) {
	db, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	ctx := context.Background()

	valid, err := db.Tokens.Issue(ctx, "alice", token.IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("create valid token: %v", err)
	}

	if _, err := db.Tokens.Lookup(ctx, valid.Secret); err != nil {
		t.Fatalf("valid token did not authenticate: %v", err)
	}

	// Issue refuses a negative TTL, so age the service instead of the token.
	aged := db.Tokens.WithClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	if _, err := aged.Lookup(ctx, valid.Secret); !errors.Is(err, token.ErrNotFound) {
		t.Errorf("expired token: err = %v, want ErrNotFound", err)
	}
}

// The secret must be reachable exactly once, and never out of the database.
func TestTokenSecretIsNotStored(t *testing.T) {
	db, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	ctx := context.Background()

	created, err := db.Tokens.Issue(ctx, "alice", token.IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	if created.Secret == "" {
		t.Fatal("Issue returned no secret")
	}
	if created.Hash == created.Secret {
		t.Error("the secret was stored as its own hash")
	}

	// Listing gives records, never the secret again.
	list, err := db.Tokens.List(ctx, "alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d tokens, want 1", len(list))
	}
	if list[0].Hash != token.Hash(created.Secret) {
		t.Error("stored hash does not match the secret")
	}

	if _, err := db.Tokens.Lookup(ctx, created.Secret+"x"); !errors.Is(err, token.ErrNotFound) {
		t.Error("a modified secret authenticated")
	}
}

// The prefix is what routes a credential to the token path instead of OIDC.
func TestTokensOwnsOnlyThisServicesPrefix(t *testing.T) {
	db, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}

	if !db.Tokens.Owns(ApiTokenPrefix + "whatever") {
		t.Error("did not recognise its own prefix")
	}
	if db.Tokens.Owns("os_mgt_whatever") {
		t.Error("claimed another service's token")
	}
}
