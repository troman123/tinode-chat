package store

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	adapter "github.com/tinode/chat/server/db"
	"github.com/tinode/chat/server/media"
	"github.com/tinode/chat/server/store/types"
)

// A server configured without a 'media' section never calls UseMediaHandler, so the
// package-level mediaHandler stays a nil interface. Client messages can still carry
// `extra.attachments` (it is an ordinary client field, not gated on anything), which
// used to reach mediaHandler.GetIdFromUrl and take the process down: a nil interface
// method call panics, and the server installs no recover anywhere.
//
// The tests below pin the two properties that fix depends on:
//   - with no media handler, the attachment paths are no-ops rather than panics;
//   - with a media handler, they behave exactly as before.
//
// Both halves matter. Only checking the first would be satisfied by disabling
// attachment linking outright.

// stubAdapter embeds the interface so the struct satisfies adapter.Adapter without spelling
// out all of its methods. Anything not overridden below is a nil call and panics, which
// is the point: it proves these paths touch only what the test declares.
type stubAdapter struct {
	adapter.Adapter

	topicUpdated  bool
	messageSaved  bool
	linkedFileIDs []string
}

func (a *stubAdapter) TopicUpdateOnMessage(topic string, msg *types.Message) error {
	a.topicUpdated = true
	return nil
}

func (a *stubAdapter) MessageSave(msg *types.Message) error {
	a.messageSaved = true
	return nil
}

func (a *stubAdapter) FileLinkAttachments(topic string, userID, msgID types.Uid, fids []string) error {
	a.linkedFileIDs = append(a.linkedFileIDs, fids...)
	return nil
}

// stubMediaHandler resolves every URL to the same non-zero file ID.
type stubMediaHandler struct{}

func (stubMediaHandler) Init(jsconf string) error { return nil }
func (stubMediaHandler) Headers(method string, u *url.URL, headers http.Header, serve bool) (http.Header, int, error) {
	return nil, 0, nil
}
func (stubMediaHandler) Upload(fdef *types.FileDef, file io.Reader) (string, int64, error) {
	return "", 0, nil
}
func (stubMediaHandler) Download(u string) (*types.FileDef, media.ReadSeekCloser, error) {
	return nil, nil, nil
}
func (stubMediaHandler) Delete(locations []string) error { return nil }
func (stubMediaHandler) GetIdFromUrl(u string) types.Uid { return types.Uid(0xF00D) }

// withStore swaps the package globals for the duration of a test and restores them.
func withStore(t *testing.T, a adapter.Adapter, mh media.Handler) {
	t.Helper()

	if err := uGen.Init(1, []byte("0123456789abcdef")); err != nil {
		t.Fatalf("uid generator: %v", err)
	}

	prevAdp, prevMedia := adp, mediaHandler
	adp, mediaHandler = a, mh
	t.Cleanup(func() { adp, mediaHandler = prevAdp, prevMedia })
}

func newMessage() *types.Message {
	return &types.Message{
		Topic: "grpTest",
		From:  types.Uid(1).UserId(),
		SeqId: 1,
	}
}

func TestMessageSaveWithAttachmentsAndNoMediaHandler(t *testing.T) {
	a := &stubAdapter{}
	withStore(t, a, nil)

	// Would panic before the fix.
	err, _ := Messages.Save(newMessage(), []string{"/v0/file/s/abcdef.jpg"}, false)
	if err != nil {
		t.Fatalf("Save: unexpected error %v", err)
	}
	if !a.topicUpdated || !a.messageSaved {
		t.Fatal("Save: the message itself must still be stored")
	}
	if len(a.linkedFileIDs) != 0 {
		t.Fatalf("Save: nothing to link without a media handler, got %v", a.linkedFileIDs)
	}
}

func TestMessageSaveWithAttachmentsAndMediaHandler(t *testing.T) {
	a := &stubAdapter{}
	withStore(t, a, stubMediaHandler{})

	err, _ := Messages.Save(newMessage(), []string{"/v0/file/s/abcdef.jpg"}, false)
	if err != nil {
		t.Fatalf("Save: unexpected error %v", err)
	}
	if len(a.linkedFileIDs) != 1 {
		t.Fatalf("Save: attachment linking must be unaffected, got %v", a.linkedFileIDs)
	}
}

func TestLinkAttachmentsWithoutMediaHandler(t *testing.T) {
	// adp stays nil on purpose: the guard has to return before any adapter call.
	withStore(t, nil, nil)

	// Would panic before the fix. Reached from {acc}, {sub} and {set}.
	if err := Files.LinkAttachments("grpTest", types.Uid(1), []string{"/v0/file/s/abcdef.jpg"}); err != nil {
		t.Fatalf("LinkAttachments: unexpected error %v", err)
	}
}

func TestLinkAttachmentsWithMediaHandler(t *testing.T) {
	a := &stubAdapter{}
	withStore(t, a, stubMediaHandler{})

	if err := Files.LinkAttachments("grpTest", types.Uid(1), []string{"/v0/file/s/abcdef.jpg"}); err != nil {
		t.Fatalf("LinkAttachments: unexpected error %v", err)
	}
	if len(a.linkedFileIDs) != 1 {
		t.Fatalf("LinkAttachments: linking must be unaffected, got %v", a.linkedFileIDs)
	}
}

func TestDeleteUnusedWithoutMediaHandler(t *testing.T) {
	// adp stays nil on purpose, as above.
	withStore(t, nil, nil)

	if err := Files.DeleteUnused(time.Now(), 10); err != nil {
		t.Fatalf("DeleteUnused: unexpected error %v", err)
	}
}

// The 'D' permission is granted per topic and carries no notion of authorship, so a
// deployment which grants it to both sides of a conversation also lets each of them erase
// the other's messages. `hard_delete_own_only` closes that by restricting a hard delete to
// the caller's own messages; these tests pin the store half of it.

// deleteCapturingAdapter records the DelMessage handed to the adapter.
type deleteCapturingAdapter struct {
	adapter.Adapter

	toDel *types.DelMessage
}

func (a *deleteCapturingAdapter) MessageDeleteList(topic string, toDel *types.DelMessage) error {
	a.toDel = toDel
	return nil
}

func (a *deleteCapturingAdapter) TopicUpdate(topic string, update map[string]any) error { return nil }

func (a *deleteCapturingAdapter) SubsUpdate(topic string, user types.Uid, update map[string]any) error {
	return nil
}

func TestDeleteListCarriesTheSenderRestriction(t *testing.T) {
	a := &deleteCapturingAdapter{}
	withStore(t, a, nil)

	sender := types.Uid(42)
	err := Messages.DeleteList("grpTest", 1, types.ZeroUid, 0, sender, []types.Range{{Low: 7, Hi: 9}})
	if err != nil {
		t.Fatalf("DeleteList: unexpected error %v", err)
	}
	got := a.toDel.GetDeleteForSender()
	if got == nil {
		t.Fatal("DeleteList: the sender restriction was dropped on the way to the adapter")
	}
	if *got != sender {
		t.Fatalf("DeleteList: restricted to %v, want %v", *got, sender)
	}
}

// An unconfigured deployment must keep behaving exactly as upstream: no restriction at all.
func TestDeleteListWithoutRestrictionLeavesItUnset(t *testing.T) {
	a := &deleteCapturingAdapter{}
	withStore(t, a, nil)

	err := Messages.DeleteList("grpTest", 1, types.ZeroUid, 0, types.ZeroUid, []types.Range{{Low: 7, Hi: 9}})
	if err != nil {
		t.Fatalf("DeleteList: unexpected error %v", err)
	}
	if got := a.toDel.GetDeleteForSender(); got != nil {
		t.Fatalf("DeleteList: unrestricted delete came out restricted to %v", *got)
	}
}

// The restriction must not be serialized: it is a query parameter, not a property of the
// delete log entry. A serialized copy would be written into dellog and read back as data.
func TestSenderRestrictionIsNotSerialized(t *testing.T) {
	dm := &types.DelMessage{Topic: "grpTest", DelId: 1}
	dm.SetDeleteForSender(types.Uid(42))

	encoded, err := json.Marshal(dm)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "eleteForSender") {
		t.Fatalf("the sender restriction leaked into the serialized form: %s", encoded)
	}
}
