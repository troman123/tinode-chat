// Regression tests for the P2P access restriction in anotherUserSub.
//
// In a P2P topic 'A' cannot be removed from either member, so every member is an
// approver and would otherwise be able to rewrite the peer's granted access. These
// tests pin both halves of the restriction: an ordinary member cannot change a
// peer's existing grant, and a root session still can.
//
// Each denial case was verified to fail without the restriction in place.
package main

import (
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/tinode/chat/server/auth"
	"github.com/tinode/chat/server/store/types"
)

// setP2PGrant has asUid attempt to change target's ModeGiven to mode.
func setP2PGrant(h *TopicTestHelper, sess *Session, asUid, target types.Uid, mode string) error {
	pkt := &ClientComMessage{
		Set: &MsgClientSet{
			Id:    "set1",
			Topic: h.topic.name,
			MsgSetQuery: MsgSetQuery{
				Sub: &MsgSetSub{User: target.UserId(), Mode: mode},
			},
		},
		AsUser:   asUid.UserId(),
		AuthLvl:  int(auth.LevelAuth),
		Original: h.topic.name,
		RcptTo:   h.topic.name,
	}
	_, err := h.topic.anotherUserSub(sess, asUid, target, false, pkt)
	return err
}

// preparePair builds a two-member P2P topic with both grants set to given.
func preparePair(t *testing.T, given types.AccessMode) *TopicTestHelper {
	t.Helper()
	globals.typesModeCP2P = types.ModeCP2P
	h := &TopicTestHelper{}
	h.setUp(t, 2, types.TopicCatP2P, "p2p-test", true)
	for _, uid := range h.uids {
		pud := h.topic.perUser[uid]
		// 'A' is always present in modeWant: both thisUserSub and the hub force
		// | ModeApprove for P2P, so hostMode = given & want always has 'A' and
		// IsAdmin() is always true. That is what makes this restriction necessary.
		pud.modeWant = types.ModeCP2P
		pud.modeGiven = given
		h.topic.perUser[uid] = pud
	}
	return h
}

// An ordinary member must not change the peer's grant, in either direction.
func TestP2POrdinaryMemberCannotChangePeerGrant(t *testing.T) {
	h := preparePair(t, types.ModeCP2P)
	defer h.tearDown()
	defer h.finish()

	for i, from := range h.uids {
		to := h.uids[i^1]
		if err := setP2PGrant(h, h.sessions[i], from, to, "JR"); err == nil {
			t.Fatalf("%s must not be allowed to change %s's ModeGiven", from.UserId(), to.UserId())
		}
		if got := h.topic.perUser[to].modeGiven; got != types.ModeCP2P {
			t.Fatalf("%s's ModeGiven must be unchanged after refusal, got %s", to.UserId(), got)
		}
	}
}

// A root session, which is how an administrative path reaches this, still can.
func TestP2PRootCanChangePeerGrant(t *testing.T) {
	h := preparePair(t, types.ModeCP2P)
	defer h.tearDown()
	defer h.finish()

	// Under on-behalf-of, pkt.AuthLvl defaults to LevelAuth (see session.go), so
	// the check reads the session's auth level, not the packet's. Reading the
	// packet would lock out the very path this test covers.
	root, _ := h.newSession("sid-root", h.uids[0])
	root.authLvl = auth.LevelRoot
	defer close(root.send)

	target := h.uids[1]
	h.ss.EXPECT().Update(h.topic.name, target, gomock.Any()).Return(nil)

	if err := setP2PGrant(h, root, h.uids[0], target, "JRA"); err != nil {
		t.Fatalf("root must be allowed, got %v", err)
	}
	// 'A' is forced back in, so the result is J|R|A.
	want := types.ModeJoin | types.ModeRead | types.ModeApprove
	if got := h.topic.perUser[target].modeGiven; got != want {
		t.Fatalf("expected ModeGiven %s after root change, got %s", want, got)
	}
}

// A grant reduced to 'A' on both sides cannot be raised by either member.
func TestP2PReducedGrantCannotBeUndoneByMembers(t *testing.T) {
	h := preparePair(t, types.ModeApprove)
	defer h.tearDown()
	defer h.finish()

	for i, from := range h.uids {
		to := h.uids[i^1]
		if err := setP2PGrant(h, h.sessions[i], from, to, "JRWPA"); err == nil {
			t.Fatalf("%s must not be able to restore %s to JRWPA", from.UserId(), to.UserId())
		}
		if got := h.topic.perUser[to].modeGiven; got != types.ModeApprove {
			t.Fatalf("reduced grant was undone: %s has %s", to.UserId(), got)
		}
	}
}

// The same for a read-only grant: neither member can restore write access.
func TestP2PReadOnlyGrantCannotBeUndoneByMembers(t *testing.T) {
	jra := types.ModeJoin | types.ModeRead | types.ModeApprove
	h := preparePair(t, jra)
	defer h.tearDown()
	defer h.finish()

	for i, from := range h.uids {
		to := h.uids[i^1]
		if err := setP2PGrant(h, h.sessions[i], from, to, "JRWPA"); err == nil {
			t.Fatalf("%s must not be able to restore %s to JRWPA", from.UserId(), to.UserId())
		}
		if got := h.topic.perUser[to].modeGiven; got != jra {
			t.Fatalf("read-only grant was undone: %s has %s", to.UserId(), got)
		}
	}
}

// Re-sending an invite without changing the mode is unaffected: the restriction
// only covers an explicit change to a different value.
func TestP2PReInviteWithoutModeChangeStillAllowed(t *testing.T) {
	h := preparePair(t, types.ModeCP2P)
	defer h.tearDown()
	defer h.finish()

	// An empty Mode keeps the existing ModeGiven and takes the ModeUnset branch,
	// which the restriction does not touch.
	if err := setP2PGrant(h, h.sessions[0], h.uids[0], h.uids[1], ""); err != nil {
		t.Fatalf("re-invite without a mode change must not be refused, got %v", err)
	}
}
