/******************************************************************************
 *
 *  Description :
 *
 *    Redaction of authentication secrets from raw JSON packets before they are
 *    written to the log. The websocket and long polling transports both hand
 *    the client's bytes to Session.dispatchRaw, which logs them before parsing.
 *
 *    The field names are the ones in logredact.go, shared with the protobuf
 *    redaction used by the gRPC transport.
 *
 *****************************************************************************/

package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// redactedJSONString renders a raw client packet for logging with the value of
// every sensitive field replaced by a placeholder. Everything else is kept:
// message names, packet ids, the authentication scheme, the user agent — a
// redacted {login} still says who tried to log in and how, which is what the
// line is read for.
//
// The packet is re-serialised from its parsed form rather than patched as text.
// A textual substitution would have to re-implement JSON string escaping to
// find where a value ends, and getting that wrong means logging the tail of a
// secret. The costs are one extra parse and serialisation per inbound packet,
// and object keys coming out in a different order than the client sent them.
//
// Redaction is unconditional; there is deliberately no "this packet looks
// harmless, log the bytes verbatim" shortcut. This function exists because the
// previous round of work concluded that one log site was the only one that
// printed raw packets and was wrong. A fast path would be one more place for
// that same judgement to be made, and to be wrong again.
func redactedJSONString(raw []byte) string {
	// UseNumber keeps numeric literals exactly as they arrived. Decoding them
	// into float64 and back would rewrite large integers in exponent notation,
	// which makes the log disagree with the packet over what was actually sent.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var parsed any
	if err := decoder.Decode(&parsed); err != nil {
		// The structure is unknown, so no part of the packet can be shown to be
		// free of credentials: a packet may well carry a valid secret and be
		// malformed only after it. The size is all that can be said safely. The
		// parse error itself is logged by the caller, which parses again.
		return "<unparsable " + strconv.Itoa(len(raw)) + " bytes>"
	}

	redactJSONValue(parsed)

	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	// The default escapes <, > and & as < and friends, which is protection
	// against JSON embedded in HTML. Nothing here is embedded in anything: this
	// is a log line, and the escaping would render the placeholder as
	// <redacted> and mangle every user agent string that contains an
	// angle bracket.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(parsed); err != nil {
		return "<unloggable " + strconv.Itoa(len(raw)) + " bytes>"
	}
	// Encode terminates the value with a newline; a log line supplies its own.
	return strings.TrimSuffix(out.String(), "\n")
}

// redactJSONValue walks a parsed JSON value and replaces the value of every
// sensitive field with the placeholder, in place.
//
// The whole value is replaced whatever its type. A secret that arrives as a
// number, an array or an object must not survive redaction just because it did
// not arrive as a string.
func redactJSONValue(val any) {
	switch typed := val.(type) {
	case map[string]any:
		// Assigning to a key that already exists is safe during a range; no key
		// is added or removed here.
		for key, item := range typed {
			if _, found := sensitiveFieldNames[canonicalFieldName(key)]; found {
				typed[key] = redactedPlaceholder
				continue
			}
			redactJSONValue(item)
		}
	case []any:
		for _, item := range typed {
			redactJSONValue(item)
		}
	}
}
