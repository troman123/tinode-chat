package main

import (
	"errors"
	"testing"

	"github.com/tinode/chat/server/auth"
	"github.com/tinode/chat/server/store/types"
)

type testP2PAuthorizer struct {
	allowed bool
	err     error
	calls   int
	remote  string
}

func (a *testP2PAuthorizer) AuthorizeP2P(_, _ types.Uid, remoteAddr string) (bool, error) {
	a.calls++
	a.remote = remoteAddr
	return a.allowed, a.err
}

func TestAuthorizeP2PCreation(t *testing.T) {
	previous := globals.p2pAuthorizer
	t.Cleanup(func() { globals.p2pAuthorizer = previous })

	requester := types.ParseUserId("usrAAAAAAAAAAA")
	target := types.ParseUserId("usrAQAAAAAAAAA")
	sess := &Session{authLvl: auth.LevelAuth, remoteAddr: "192.0.2.15"}

	t.Run("disabled preserves upstream behavior", func(t *testing.T) {
		globals.p2pAuthorizer = nil
		if err := authorizeP2PCreation(requester, target, sess); err != nil {
			t.Fatalf("disabled hook denied creation: %v", err)
		}
	})

	t.Run("explicit allow", func(t *testing.T) {
		fake := &testP2PAuthorizer{allowed: true}
		globals.p2pAuthorizer = fake
		if err := authorizeP2PCreation(requester, target, sess); err != nil {
			t.Fatalf("allowed creation was denied: %v", err)
		}
		if fake.calls != 1 || fake.remote != sess.remoteAddr {
			t.Fatalf("unexpected authorizer call: %+v", fake)
		}
	})

	t.Run("explicit deny", func(t *testing.T) {
		globals.p2pAuthorizer = &testP2PAuthorizer{allowed: false}
		if err := authorizeP2PCreation(requester, target, sess); !errors.Is(err, types.ErrPermissionDenied) {
			t.Fatalf("deny returned %v", err)
		}
	})

	t.Run("transport failure denies", func(t *testing.T) {
		globals.p2pAuthorizer = &testP2PAuthorizer{err: errors.New("policy unavailable")}
		if err := authorizeP2PCreation(requester, target, sess); !errors.Is(err, types.ErrPermissionDenied) {
			t.Fatalf("failure returned %v", err)
		}
	})

	t.Run("root administrative path bypasses hook", func(t *testing.T) {
		fake := &testP2PAuthorizer{allowed: false}
		globals.p2pAuthorizer = fake
		root := &Session{authLvl: auth.LevelRoot}
		if err := authorizeP2PCreation(requester, target, root); err != nil {
			t.Fatalf("root was denied: %v", err)
		}
		if fake.calls != 0 {
			t.Fatalf("root unexpectedly called policy %d time(s)", fake.calls)
		}
	})
}
