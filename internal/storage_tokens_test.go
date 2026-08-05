package app

import (
	"context"
	"strings"
	"testing"
	"time"
)

// An expired token must not authenticate. The lazy cleanup in GetTokens only
// runs when the owner lists their tokens, so the expiry has to be enforced on
// the lookup path itself.
func TestExpiredTokenDoesNotAuthenticate(t *testing.T) {
	db, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	ctx := context.Background()

	valid, err := db.CreateToken(ctx, "alice", time.Hour, false)
	if err != nil {
		t.Fatalf("create valid token: %v", err)
	}
	expired, err := db.CreateToken(ctx, "alice", -time.Minute, false)
	if err != nil {
		t.Fatalf("create expired token: %v", err)
	}

	got, err := db.GetToken(ctx, valid.TokenString)
	if err != nil || got == nil {
		t.Fatalf("valid token should authenticate, got (%v, %v)", got, err)
	}

	got, err = db.GetToken(ctx, expired.TokenString)
	if err != nil {
		t.Fatalf("lookup of expired token errored: %v", err)
	}
	if got != nil {
		t.Errorf("expired token still authenticates: %+v", got)
	}
}

// The database must never hold a usable token: only its hash, plus a short
// prefix for identification. The token itself exists once, in the create call.
func TestTokensAreStoredHashed(t *testing.T) {
	db, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	ctx := context.Background()

	created, err := db.CreateToken(ctx, "alice", time.Hour, false)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if created.TokenString == "" {
		t.Fatal("create must return the token exactly once")
	}

	var stored Token
	if err := db.db.WithContext(ctx).Where("id = ?", created.ID).Take(&stored).Error; err != nil {
		t.Fatalf("read back token: %v", err)
	}
	if stored.TokenString != "" {
		t.Errorf("token was persisted in the clear: %q", stored.TokenString)
	}
	if stored.TokenHash != HashToken(created.TokenString) {
		t.Errorf("stored hash %q does not match the token", stored.TokenHash)
	}
	if !strings.HasPrefix(created.TokenString, stored.TokenPrefix) || len(stored.TokenPrefix) >= len(created.TokenString) {
		t.Errorf("prefix %q is not a proper identifying head of the token", stored.TokenPrefix)
	}

	// And the hashed token still authenticates.
	if got, err := db.GetToken(ctx, created.TokenString); err != nil || got == nil {
		t.Fatalf("hashed token should authenticate, got (%v, %v)", got, err)
	}
	// A wrong token does not.
	if got, _ := db.GetToken(ctx, created.TokenString+"x"); got != nil {
		t.Error("a modified token must not authenticate")
	}
}
