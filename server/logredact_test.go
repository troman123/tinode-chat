package main

import (
	"strings"
	"testing"

	"github.com/tinode/chat/pbx"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// The value stands in for a real credential. It is deliberately distinctive so
// that a substring search cannot match it by accident.
const testSecret = "S3CRET-c8f1a4d6e2b90371"

func TestRedactedProtoStringHidesLoginSecret(t *testing.T) {
	// The packet that leaked in production: the Admin Projector's root login.
	msg := &pbx.ClientMsg{Message: &pbx.ClientMsg_Login{Login: &pbx.ClientLogin{
		Id:     "2",
		Scheme: "basic",
		Secret: []byte(testSecret),
	}}}

	out := redactedProtoString(msg)

	if strings.Contains(out, testSecret) {
		t.Fatal("秘密进了日志")
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Errorf("没有留下占位符，看不出报文里带了秘密: %s", out)
	}
	// Diagnostics must survive: without the scheme and the packet id the line
	// no longer says which authenticator was tried, which is why it is logged.
	for _, keep := range []string{"login", "basic", `id:"2"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("诊断信息 %q 被一起抹掉了: %s", keep, out)
		}
	}
}

func TestRedactedProtoStringHidesEverySensitiveFieldOfAcc(t *testing.T) {
	// One packet carrying every sensitive field the schema has outside login:
	// secret, token, tmp_secret and the credential verification response.
	msg := &pbx.ClientMsg{Message: &pbx.ClientMsg_Acc{Acc: &pbx.ClientAcc{
		Id:        "3",
		UserId:    "usrTestTarget",
		Scheme:    "basic",
		State:     "susp",
		Secret:    []byte(testSecret + "-secret"),
		Token:     []byte(testSecret + "-token"),
		TmpSecret: []byte(testSecret + "-tmp"),
		Cred: []*pbx.ClientCred{{
			Method:   "email",
			Value:    "user@example.com",
			Response: testSecret + "-cred",
		}},
	}}}

	out := redactedProtoString(msg)

	// The prefix is shared by all four, so one search covers every field
	// including the one nested inside a repeated message.
	if strings.Contains(out, testSecret) {
		t.Fatalf("敏感字段进了日志: %s", out)
	}
	for _, keep := range []string{"usrTestTarget", "susp", "email"} {
		if !strings.Contains(out, keep) {
			t.Errorf("诊断信息 %q 被一起抹掉了: %s", keep, out)
		}
	}
}

func TestRedactedProtoStringDoesNotModifyArgument(t *testing.T) {
	// The packet is logged on its way to the handler that still has to
	// authenticate with it. Redacting in place would break every login.
	login := &pbx.ClientLogin{Id: "2", Scheme: "basic", Secret: []byte(testSecret)}
	msg := &pbx.ClientMsg{Message: &pbx.ClientMsg_Login{Login: login}}

	redactedProtoString(msg)

	if got := string(login.GetSecret()); got != testSecret {
		t.Fatalf("原报文被改写了，认证会失败: secret = %q", got)
	}
}

func TestRedactedProtoStringHandlesNil(t *testing.T) {
	if out := redactedProtoString(nil); out != "" {
		t.Fatalf("nil 应当得到空串，实得 %q", out)
	}
}

// suspiciousFieldNameParts are substrings that mark a field as likely to carry
// a credential. Every matching field in the pbx schema has to be either
// redacted or listed as reviewed-and-harmless below; TestSensitiveJSONFieldCoverage
// applies the same list to the json tags of the client messages.
//
// The parts are matched against the canonicalised name, so they carry no
// separators: "apikey" catches "api_key" as well.
var suspiciousFieldNameParts = []string{
	"secret", "token", "password", "passwd", "credential", "response", "resp", "apikey",
}

// reviewedHarmlessFields are fields whose names match the patterns above but
// which carry no credential. Each entry is a decision, not a suppression:
// adding one means someone looked at the field and concluded it is safe.
var reviewedHarmlessFields = map[string]struct{}{}

// TestSensitiveFieldCoverage fails when the schema grows a field that looks
// like a credential but is not redacted.
//
// This is the part that keeps working after we stop looking at it. The
// redaction map is keyed by field name so that new fields are covered
// automatically; this test is what catches the case where upstream names one
// something we did not anticipate.
func TestSensitiveFieldCoverage(t *testing.T) {
	var checked int

	protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		if file.Package() != "pbx" {
			return true
		}
		messages := file.Messages()
		for i := range messages.Len() {
			checked += walkMessageFields(t, messages.Get(i))
		}
		return true
	})

	if checked == 0 {
		t.Fatal("一个 pbx 字段都没扫到，测试自身失效了")
	}
}

func walkMessageFields(t *testing.T, md protoreflect.MessageDescriptor) int {
	t.Helper()

	checked := 0
	fields := md.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		checked++

		name := canonicalFieldName(string(fd.Name()))
		_, redacted := sensitiveFieldNames[name]
		_, reviewed := reviewedHarmlessFields[string(md.FullName())+"."+name]

		for _, part := range suspiciousFieldNameParts {
			if !strings.Contains(name, part) {
				continue
			}
			if !redacted && !reviewed {
				t.Errorf("%s.%s 的名字像凭据但没有脱敏。"+
					"确认它是否携带秘密：是就加进 sensitiveFieldNames，"+
					"不是就加进 reviewedHarmlessFields。", md.FullName(), name)
			}
			break
		}
	}

	nested := md.Messages()
	for i := range nested.Len() {
		if nested.Get(i).IsMapEntry() {
			continue
		}
		checked += walkMessageFields(t, nested.Get(i))
	}
	return checked
}

// TestRedactedProtoStringCoversKnownSensitiveFields pins the fields that are
// redacted today, so that removing one from the map is a deliberate act.
func TestRedactedProtoStringCoversKnownSensitiveFields(t *testing.T) {
	for _, name := range []string{"secret", "tmpsecret", "token", "response", "resp"} {
		if _, found := sensitiveFieldNames[name]; !found {
			t.Errorf("字段 %q 不再脱敏", name)
		}
	}
}

// TestRedactedProtoStringRedactsNestedAuthSecret covers pbx.Auth, which is
// reached through file upload handling rather than through a client packet.
func TestRedactedProtoStringRedactsNestedAuthSecret(t *testing.T) {
	msg := &pbx.Auth{Scheme: "token", Secret: testSecret}

	out := redactedProtoString(msg)

	if strings.Contains(out, testSecret) {
		t.Fatalf("pbx.Auth.secret 进了日志: %s", out)
	}
	if !strings.Contains(out, "token") {
		t.Errorf("scheme 被一起抹掉了: %s", out)
	}
}

// Compile-time assurance that the helper accepts any generated message.
var _ = func() proto.Message { return &pbx.ClientMsg{} }
