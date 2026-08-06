/******************************************************************************
 *
 *  Description :
 *
 *    Redaction of authentication secrets from protobuf messages before they are
 *    written to the log.
 *
 *****************************************************************************/

package main

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// redactedPlaceholder replaces the value of a sensitive field. It is a fixed
// string: the length of a secret is itself information, so the placeholder must
// not vary with the value it hides.
const redactedPlaceholder = "<redacted>"

// sensitiveFieldNames lists protobuf field names whose values must never reach
// the log. Matching is by name rather than by an explicit list of messages so
// that a field added upstream later is redacted the day it appears, instead of
// leaking until someone remembers to extend a list here.
//
// In the current schema this covers ClientLogin.secret, ClientAcc.secret,
// ClientAcc.token, ClientAcc.tmp_secret, ClientCred.response and Auth.secret.
var sensitiveFieldNames = map[protoreflect.Name]struct{}{
	"secret":     {},
	"tmp_secret": {},
	"token":      {},
	"password":   {},
	"response":   {},
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
		if _, found := sensitiveFieldNames[fd.Name()]; found {
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
