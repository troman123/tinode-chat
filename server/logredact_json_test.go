package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/tinode/chat/server/logs"
)

// wireSecret is how a secret appears in a JSON packet. MsgClientLogin.Secret and
// MsgClientAcc.Secret are []byte, which encoding/json reads from a base64
// string, so the plain text never appears on the wire — and a test searching
// only for the plain text would pass while the encoded secret sat in the log.
func wireSecret(plain string) string {
	return base64.StdEncoding.EncodeToString([]byte(plain))
}

// A {login} packet of the shape that put a secret into the log: a one-time
// secret issued by an external authenticator, sent right after {hi}.
var testLoginPacket = `{"login":{"id":"75307","scheme":"basic",` +
	`"secret":"` + wireSecret(testSecret) + `"}}`

func TestRedactedJSONStringHidesLoginSecret(t *testing.T) {
	out := redactedJSONString([]byte(testLoginPacket))

	if strings.Contains(out, wireSecret(testSecret)) {
		t.Fatalf("秘密进了日志: %s", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Errorf("没有留下占位符，看不出报文里带了秘密: %s", out)
	}
	// Diagnostics must survive: without the scheme and the packet id the line no
	// longer says which authenticator was tried, which is why it is logged.
	for _, keep := range []string{"login", "basic", `"id":"75307"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("诊断信息 %q 被一起抹掉了: %s", keep, out)
		}
	}
}

func TestRedactedJSONStringHidesEverySensitiveFieldOfAcc(t *testing.T) {
	// One packet carrying every sensitive field the JSON schema has outside
	// {login}: the shared secret, the temporary secret and the credential
	// verification code, the last one nested inside an array.
	// resp is a plain string on the wire; the other two are base64.
	secret, tmpSecret, cred := wireSecret(testSecret+"-secret"), wireSecret(testSecret+"-tmp"), testSecret+"-cred"
	raw := `{"acc":{"id":"3","user":"newXYZ","scheme":"basic","status":"susp",` +
		`"secret":"` + secret + `",` +
		`"tmpsecret":"` + tmpSecret + `",` +
		`"cred":[{"meth":"email","val":"user@example.com","resp":"` + cred + `"}]}}`

	out := redactedJSONString([]byte(raw))

	// Every field is checked separately, including the one nested in the array:
	// base64 of a shared plain text prefix shares a prefix too, so a single
	// search could pass while one of the three was still in the output.
	for _, leaked := range []string{secret, tmpSecret, cred} {
		if strings.Contains(out, leaked) {
			t.Errorf("敏感字段进了日志: %s", out)
		}
	}
	for _, keep := range []string{"newXYZ", "susp", "email", "user@example.com"} {
		if !strings.Contains(out, keep) {
			t.Errorf("诊断信息 %q 被一起抹掉了: %s", keep, out)
		}
	}
}

func TestRedactedJSONStringKeepsHandshakeVerbatim(t *testing.T) {
	// {hi} carries no credential. It is the packet the log is most often read
	// for — client version and platform — and it must come through untouched.
	raw := `{"hi":{"id":"75306","ver":"0.23","lang":"en_AS",` +
		`"ua":"Example (iOS ; en_AS); tinode-swift/1.0.0"}}`

	out := redactedJSONString([]byte(raw))

	if strings.Contains(out, redactedPlaceholder) {
		t.Errorf("{hi} 里没有秘密，不该有任何字段被脱敏: %s", out)
	}
	for _, keep := range []string{"0.23", "en_AS", "tinode-swift/1.0.0"} {
		if !strings.Contains(out, keep) {
			t.Errorf("诊断信息 %q 丢了: %s", keep, out)
		}
	}
}

// TestRedactedJSONStringMatchesKeysTheParserAccepts covers the gap between what
// the redaction looks for and what the server actually reads. encoding/json
// matches object keys to struct fields case-insensitively, so a client can send
// "SECRET" and be authenticated by it. Redacting only the lower case spelling
// would leave a working way to put a secret in the log.
func TestRedactedJSONStringMatchesKeysTheParserAccepts(t *testing.T) {
	raw := `{"login":{"id":"1","scheme":"basic","SeCrEt":"` + wireSecret(testSecret) + `"}}`

	// First: the server really does accept the odd spelling. If upstream ever
	// switches to a strict decoder this assertion fails, and the case-folding in
	// canonicalFieldName can be dropped along with it.
	var parsed ClientComMessage
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if parsed.Login == nil {
		t.Fatal("前提不成立：报文里没有 {login}")
	}
	if got := string(parsed.Login.Secret); got != testSecret {
		t.Fatalf("前提不成立：解析器没有接受这个拼写，secret = %q", got)
	}

	if out := redactedJSONString([]byte(raw)); strings.Contains(out, wireSecret(testSecret)) {
		t.Fatalf("大小写变体绕过了脱敏: %s", out)
	}
}

// TestRedactedJSONStringRedactsNonStringValues guards the assumption that a
// secret arrives as a string. It does not have to: the value is replaced
// whatever its JSON type.
func TestRedactedJSONStringRedactsNonStringValues(t *testing.T) {
	for name, raw := range map[string]string{
		"number": `{"login":{"secret":9876543210123456789}}`,
		"array":  `{"login":{"secret":["` + testSecret + `"]}}`,
		"object": `{"login":{"secret":{"inner":"` + testSecret + `"}}}`,
	} {
		out := redactedJSONString([]byte(raw))
		if strings.Contains(out, testSecret) || strings.Contains(out, "9876543210123456789") {
			t.Errorf("%s 形态的 secret 没被脱敏: %s", name, out)
		}
	}
}

// TestRedactedJSONStringRefusesUnparsablePacket is the case that makes the
// order in dispatchRaw matter. A packet truncated after the secret still
// contains the secret, so the bytes must not be logged just because they did
// not parse.
func TestRedactedJSONStringRefusesUnparsablePacket(t *testing.T) {
	raw := `{"login":{"scheme":"basic","secret":"` + testSecret

	out := redactedJSONString([]byte(raw))

	if strings.Contains(out, testSecret) {
		t.Fatalf("解析失败的报文被原样打了出来: %s", out)
	}
	if !strings.Contains(out, "unparsable") {
		t.Errorf("应当说明报文没解析出来: %s", out)
	}
}

// TestRedactedJSONStringDoesNotModifyArgument mirrors the protobuf case: the
// packet is logged on its way to the handler that still has to authenticate
// with it.
func TestRedactedJSONStringDoesNotModifyArgument(t *testing.T) {
	raw := []byte(testLoginPacket)
	before := string(raw)

	redactedJSONString(raw)

	if string(raw) != before {
		t.Fatalf("原报文被改写了，认证会失败: %s", raw)
	}
}

func TestRedactedJSONStringPreservesLargeNumbers(t *testing.T) {
	// Round-tripping through float64 would rewrite this as 1.2345678901234568e+18
	// and the log would disagree with the packet about what was sent.
	raw := `{"del":{"id":"5","topic":"grpTest","delseq":[{"low":1234567890123456789}]}}`

	if out := redactedJSONString([]byte(raw)); !strings.Contains(out, "1234567890123456789") {
		t.Errorf("大整数被改写了: %s", out)
	}
}

// TestDispatchRawKeepsTheSecretOutOfTheLog covers the call site rather than the
// helper. A correct redactedJSONString is worth nothing if dispatchRaw goes back
// to printing the raw bytes, and that is exactly the regression this file exists
// to prevent — the leak was one Printf, not a missing function.
func TestDispatchRawKeepsTheSecretOutOfTheLog(t *testing.T) {
	// A packet truncated in the middle of the secret would not prove anything:
	// the search would miss it because it is no longer there in full. This one
	// is cut after the secret, which is the dangerous shape — a packet that
	// carries a whole credential and still does not parse.
	truncated := `{"login":{"scheme":"basic","secret":"` + wireSecret(testSecret) + `"`

	for name, raw := range map[string]string{
		// Goes through dispatch: with s.ver == 0 the {login} handler is refused
		// as out of sequence before it reaches the store, so no mock is needed.
		"parsed":    testLoginPacket,
		"truncated": truncated,
	} {
		t.Run(name, func(t *testing.T) {
			var captured bytes.Buffer
			info, warn, err := logs.Info, logs.Warn, logs.Err
			logs.Init(&captured, "stdFlags")
			defer func() { logs.Info, logs.Warn, logs.Err = info, warn, err }()

			s := &Session{send: make(chan any, 10), sid: "test-sid"}
			s.dispatchRaw([]byte(raw))

			if out := captured.String(); strings.Contains(out, wireSecret(testSecret)) {
				t.Fatalf("秘密写进了日志: %s", out)
			}
			if captured.Len() == 0 {
				t.Error("什么都没记，日志失去了诊断作用")
			}
		})
	}
}

// TestSensitiveJSONFieldCoverage is the JSON counterpart of
// TestSensitiveFieldCoverage: it fails when a client message grows a field that
// looks like a credential but is not redacted.
//
// It walks the json struct tags of ClientComMessage, which is the complete set
// of fields a client can send over websocket or long polling. Both tests use
// the same suspiciousFieldNameParts, so a name that is caught on one wire
// format cannot be missed on the other.
func TestSensitiveJSONFieldCoverage(t *testing.T) {
	checked := walkJSONFields(t, reflect.TypeOf(ClientComMessage{}), map[reflect.Type]bool{})

	if checked == 0 {
		t.Fatal("一个 json 字段都没扫到，测试自身失效了")
	}
}

// reviewedHarmlessJSONFields are json field names that match the patterns but
// carry no credential. Each entry is a decision, not a suppression.
var reviewedHarmlessJSONFields = map[string]struct{}{}

func walkJSONFields(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) int {
	t.Helper()

	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return 0
	}
	seen[typ] = true

	checked := 0
	for i := range typ.NumField() {
		field := typ.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			// No tag: encoding/json falls back to the Go field name.
			name = field.Name
		}
		checked++

		canonical := canonicalFieldName(name)
		_, redacted := sensitiveFieldNames[canonical]
		_, reviewed := reviewedHarmlessJSONFields[typ.Name()+"."+name]

		for _, part := range suspiciousFieldNameParts {
			if !strings.Contains(canonical, part) {
				continue
			}
			if !redacted && !reviewed {
				t.Errorf("%s.%s 的名字像凭据但没有脱敏。"+
					"确认它是否携带秘密：是就加进 sensitiveFieldNames，"+
					"不是就加进 reviewedHarmlessJSONFields。", typ.Name(), name)
			}
			break
		}

		checked += walkJSONFields(t, field.Type, seen)
	}
	return checked
}

// TestCanonicalFieldNameJoinsTheTwoSpellings pins the reason the two paths can
// share one set of names.
func TestCanonicalFieldNameJoinsTheTwoSpellings(t *testing.T) {
	for _, spelling := range []string{"tmp_secret", "tmpsecret", "TmpSecret", "TMP-SECRET"} {
		if got := canonicalFieldName(spelling); got != "tmpsecret" {
			t.Errorf("canonicalFieldName(%q) = %q，与另一侧对不上", spelling, got)
		}
	}
	if got := canonicalFieldName("secret"); got != "secret" {
		t.Errorf("已经是规范形式的名字不该被改动: %q", got)
	}
}
