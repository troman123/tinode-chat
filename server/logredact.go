/******************************************************************************
 *
 *  Description :
 *
 *    Redaction of authentication secrets from protobuf messages before they are
 *    written to the log. The set of field names defined here is shared with the
 *    JSON redaction in logredact_json.go.
 *
 *****************************************************************************/

package main

import (
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// redactedPlaceholder replaces the value of a sensitive field. It is a fixed
// string: the length of a secret is itself information, so the placeholder must
// not vary with the value it hides.
const redactedPlaceholder = "<redacted>"

// sensitiveFieldNames lists the field names whose values must never reach the
// log. Matching is by name rather than by an explicit list of messages so that
// a field added upstream later is redacted the day it appears, instead of
// leaking until someone remembers to extend a list here.
//
// The set is shared by both redaction paths — the protobuf one below and the
// JSON one in logredact_json.go. The two wire formats carry the same
// credentials, and a set maintained once per path only ever gets extended on
// the path someone happened to be looking at.
//
// Names are stored canonicalised (see canonicalFieldName), so one entry covers
// both spellings of a field whose protobuf and JSON names differ only in
// separators or case.
//
// In the protobuf schema this covers ClientLogin.secret, ClientAcc.secret,
// ClientAcc.token, ClientAcc.tmp_secret, ClientCred.response and Auth.secret;
// in the JSON schema {login}.secret, {acc}.secret, {acc}.tmpsecret and the
// credential verification code {cred}.resp.
var sensitiveFieldNames = map[string]struct{}{
	"secret":    {},
	"tmpsecret": {},
	"token":     {},
	"password":  {},
	"response":  {},
	"resp":      {},
}

// canonicalFieldName reduces a field name to the form used as a key in
// sensitiveFieldNames: lower case, separators removed.
//
// Two things make the raw name unusable as a key. The wire formats spell the
// same field differently — protobuf `tmp_secret` is `tmpsecret` in JSON — and
// encoding/json matches object keys to struct fields case-insensitively, so a
// client may send `Secret` and still be understood by the parser. Redaction has
// to cover everything the parser accepts, not just the canonical spelling.
func canonicalFieldName(name string) string {
	if !needsCanonicalisation(name) {
		return name
	}
	var out strings.Builder
	out.Grow(len(name))
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c == '_' || c == '-':
		case c >= 'A' && c <= 'Z':
			out.WriteByte(c + ('a' - 'A'))
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

// needsCanonicalisation reports whether canonicalFieldName would change the
// name. Almost every field is already canonical; checking first keeps the
// common case free of an allocation, on a path that runs for every field of
// every logged packet.
func needsCanonicalisation(name string) bool {
	for i := 0; i < len(name); i++ {
		if c := name[i]; c == '_' || c == '-' || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// redactedProtoString renders a protobuf message for logging with every
// sensitive field replaced by a placeholder.
//
// Everything else is preserved verbatim, including the message and field names,
// the packet id, the authentication scheme and the account state — a redacted
// login packet still says who tried to log in with which scheme and whether a
// secret was supplied at all, which is what the log is read for.
//
// The argument is never modified: the message is being logged on its way to the
// handler that still has to authenticate with it. Redaction operates on a clone.
func redactedProtoString(msg proto.Message) string {
	if msg == nil {
		return ""
	}
	clone := proto.Clone(msg)
	redactMessage(clone.ProtoReflect())
	if s, ok := clone.(interface{ String() string }); ok {
		return s.String()
	}
	// Generated message types all implement String(). A type that does not is
	// better logged as nothing than as an unredacted fallback.
	return ""
}

// redactMessage walks a message and redacts sensitive fields in place,
// descending into nested messages, repeated fields and map values.
func redactMessage(msg protoreflect.Message) {
	if !msg.IsValid() {
		return
	}

	// Collected first, applied after: Range does not define behaviour when the
	// message is mutated while it is iterating.
	var sensitive []protoreflect.FieldDescriptor
	var descend []protoreflect.Message

	msg.Range(func(fd protoreflect.FieldDescriptor, val protoreflect.Value) bool {
		if _, found := sensitiveFieldNames[canonicalFieldName(string(fd.Name()))]; found {
			sensitive = append(sensitive, fd)
			return true
		}

		switch {
		case fd.IsMap():
			if fd.MapValue().Message() != nil {
				val.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
					descend = append(descend, item.Message())
					return true
				})
			}
		case fd.IsList():
			if fd.Message() != nil {
				list := val.List()
				for i := range list.Len() {
					descend = append(descend, list.Get(i).Message())
				}
			}
		case fd.Message() != nil:
			descend = append(descend, val.Message())
		}
		return true
	})

	for _, fd := range sensitive {
		redactField(msg, fd)
	}
	for _, nested := range descend {
		redactMessage(nested)
	}
}

// redactField replaces one field's value with the placeholder.
//
// A repeated or map field cannot hold a scalar placeholder, and neither can a
// numeric one. Those are cleared instead: dropping the field is a loss of the
// "a value was present" signal, but it is the only option that cannot leak.
func redactField(msg protoreflect.Message, fd protoreflect.FieldDescriptor) {
	if fd.IsList() || fd.IsMap() {
		msg.Clear(fd)
		return
	}
	switch fd.Kind() {
	case protoreflect.StringKind:
		msg.Set(fd, protoreflect.ValueOfString(redactedPlaceholder))
	case protoreflect.BytesKind:
		msg.Set(fd, protoreflect.ValueOfBytes([]byte(redactedPlaceholder)))
	default:
		msg.Clear(fd)
	}
}
