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

// Reducing one member to A evicts that member's ordinary clients, but must retain
// a pre-attached root management stream long enough to update the other member.
// Otherwise a two-sided block always stops halfway: the first write evicts the
// actor required by the second write.
func TestP2PRootTwoSidedReductionKeepsManagementStreams(t *testing.T) {
	h := preparePair(t, types.ModeCP2P)
	defer h.tearDown()
	defer h.finish()

	rootA, _ := h.newSession("sid-root-a", h.uids[0])
	rootA.authLvl = auth.LevelRoot
	defer close(rootA.send)
	rootB, _ := h.newSession("sid-root-b", h.uids[1])
	rootB.authLvl = auth.LevelRoot
	defer close(rootB.send)

	h.topic.sessions[rootA] = perSessionData{uid: h.uids[0]}
	h.topic.sessions[rootB] = perSessionData{uid: h.uids[1]}
	// The real network session owns a route to the topic in addition to the
	// topic-side sessions map. ACL eviction must clear both synchronously.
	h.sessions[0].addSub(h.topic.name, &Subscription{})
	h.sessions[1].addSub(h.topic.name, &Subscription{})
	for _, uid := range h.uids {
		pud := h.topic.perUser[uid]
		pud.online++
		h.topic.perUser[uid] = pud
	}

	h.ss.EXPECT().Update(h.topic.name, h.uids[1], gomock.Any()).Return(nil)
	if err := setP2PGrant(h, rootA, h.uids[0], h.uids[1], "A"); err != nil {
		t.Fatalf("first root reduction failed: %v", err)
	}
	if _, ok := h.topic.sessions[h.sessions[1]]; ok {
		t.Fatal("ordinary target client must be evicted immediately")
	}
	if h.sessions[1].getSub(h.topic.name) != nil {
		t.Fatal("ordinary target route must be removed before ACL update returns")
	}
	if _, ok := h.topic.sessions[rootB]; !ok {
		t.Fatal("root stream for the second half must remain attached")
	}

	h.ss.EXPECT().Update(h.topic.name, h.uids[0], gomock.Any()).Return(nil)
	if err := setP2PGrant(h, rootB, h.uids[1], h.uids[0], "A"); err != nil {
		t.Fatalf("second root reduction failed: %v", err)
	}

	for i, uid := range h.uids {
		if got := h.topic.perUser[uid].modeGiven; got != types.ModeApprove {
			t.Fatalf("member %d grant = %s, want A", i, got)
		}
		if _, ok := h.topic.sessions[h.sessions[i]]; ok {
			t.Fatalf("ordinary client %d remained attached", i)
		}
		if h.sessions[i].getSub(h.topic.name) != nil {
			t.Fatalf("ordinary client %d retained a stale publish route", i)
		}
	}
	if _, ok := h.topic.sessions[rootA]; !ok {
		t.Fatal("first root stream must remain until projector cleanup")
	}
	if _, ok := h.topic.sessions[rootB]; !ok {
		t.Fatal("second root stream must remain until projector cleanup")
	}
}

// Once a revoked P2P member has been detached, the next publish must expose the
// persisted ACL decision as 403 rather than a generic 409 attach-order error.
func TestP2PRevokedDetachedPublishGetsPermissionDenied(t *testing.T) {
	h := preparePair(t, types.ModeCP2P)
	defer h.tearDown()

	uid := h.uids[0]
	h.ss.EXPECT().Get(h.topic.name, uid, false).Return(&types.Subscription{
		Topic:     h.topic.name,
		User:      uid.String(),
		ModeWant:  types.ModeCP2P,
		ModeGiven: types.ModeApprove,
	}, nil)

	h.sessions[0].publish(&ClientComMessage{
		Pub:      &MsgClientPub{Id: "pub-denied", Topic: h.topic.name, Content: "probe"},
		AsUser:   uid.UserId(),
		Original: h.topic.name,
		RcptTo:   h.topic.name,
	})
	h.finish()

	if len(h.results[0].messages) != 1 {
		t.Fatalf("expected one denial response, got %d", len(h.results[0].messages))
	}
	reply, ok := h.results[0].messages[0].(*ServerComMessage)
	if !ok || reply.Ctrl == nil || reply.Ctrl.Code != 403 {
		t.Fatalf("expected explicit 403 denial, got %#v", h.results[0].messages[0])
	}
}

// A retry may start after the previous process committed just one side to A.
// Root must be able to attach on behalf of that existing banned subscription so
// the retry can finish the peer, without changing ModeWant or ModeGiven.
func TestP2PRootCanAttachExistingBannedSubscriptionForRecovery(t *testing.T) {
	h := preparePair(t, types.ModeCP2P)
	defer h.tearDown()
	defer h.finish()

	banned := h.uids[0]
	pud := h.topic.perUser[banned]
	pud.modeGiven = types.ModeApprove
	h.topic.perUser[banned] = pud

	root, _ := h.newSession("sid-root-recovery", banned)
	root.authLvl = auth.LevelRoot
	defer close(root.send)
	pkt := &ClientComMessage{
		Sub:      &MsgClientSub{Id: "sub-recovery", Topic: h.topic.name},
		AsUser:   banned.UserId(),
		AuthLvl:  int(auth.LevelAuth),
		Original: h.topic.name,
		RcptTo:   h.topic.name,
		sess:     root,
	}
	if err := h.topic.subscriptionReply(false, pkt); err != nil {
		t.Fatalf("root recovery attachment failed: %v", err)
	}
	if _, ok := h.topic.sessions[root]; !ok {
		t.Fatal("root recovery stream was not attached")
	}
	got := h.topic.perUser[banned]
	if got.modeWant != types.ModeCP2P || got.modeGiven != types.ModeApprove {
		t.Fatalf("recovery attach changed user ACL: want=%s given=%s", got.modeWant, got.modeGiven)
	}
}

func TestP2POrdinaryClientCannotAttachExistingBannedSubscription(t *testing.T) {
	h := preparePair(t, types.ModeCP2P)
	defer h.tearDown()
	defer h.finish()

	banned := h.uids[0]
	pud := h.topic.perUser[banned]
	pud.modeGiven = types.ModeApprove
	h.topic.perUser[banned] = pud

	ordinary, _ := h.newSession("sid-ordinary-recovery", banned)
	ordinary.authLvl = auth.LevelAuth
	defer close(ordinary.send)
	pkt := &ClientComMessage{
		Sub:      &MsgClientSub{Id: "sub-denied", Topic: h.topic.name},
		AsUser:   banned.UserId(),
		AuthLvl:  int(auth.LevelAuth),
		Original: h.topic.name,
		RcptTo:   h.topic.name,
		sess:     ordinary,
	}
	if err := h.topic.subscriptionReply(false, pkt); err == nil {
		t.Fatal("ordinary banned client unexpectedly attached")
	}
	if _, ok := h.topic.sessions[ordinary]; ok {
		t.Fatal("ordinary banned client appears in topic sessions")
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
