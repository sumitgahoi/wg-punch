//go:build integration

package stunprobe

import "testing"

func TestResolveRoute(t *testing.T) {
	local, remote, err := resolveRoute("stun.cloudflare.com:3478")
	if err != nil {
		t.Fatal(err)
	}

	if !local.IsValid() || !local.Is4() {
		t.Fatalf("invalid local IPv4 address: %v", local)
	}

	if !remote.Addr().IsValid() || !remote.Addr().Is4() {
		t.Fatalf("invalid remote IPv4 address: %v", remote)
	}

	if remote.Port() != 3478 {
		t.Fatalf("unexpected remote port: %d", remote.Port())
	}
}