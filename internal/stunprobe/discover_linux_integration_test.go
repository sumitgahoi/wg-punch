//go:build integration

package stunprobe

import (
	"context"
	"testing"
	"time"
)

func TestDiscover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	candidate, err := Discover(
		ctx,
		51820,
		"stun.cloudflare.com:3478",
	)
	if err != nil {
		t.Fatal(err)
	}

	if !candidate.IsValid() {
		t.Fatal("invalid candidate")
	}

	if !candidate.Addr().Is4() {
		t.Fatalf("candidate is not IPv4: %v", candidate)
	}

	t.Logf("public candidate: %v", candidate)
}