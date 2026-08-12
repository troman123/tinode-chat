package rest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tinode/chat/server/store/types"
)

func ecKeyPEM(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestNewRequestSignerRejectsBadConfig(t *testing.T) {
	_, keyPEM := ecKeyPEM(t, elliptic.P256())
	_, p384PEM := ecKeyPEM(t, elliptic.P384())

	base := func() *serviceJWTConfig {
		return &serviceJWTConfig{PrivateKeyPEM: keyPEM, Kid: "k1", Issuer: "iss", Audience: "aud"}
	}

	cases := []struct {
		name   string
		mangle func(*serviceJWTConfig)
	}{
		{"no kid", func(c *serviceJWTConfig) { c.Kid = "" }},
		{"no issuer", func(c *serviceJWTConfig) { c.Issuer = "" }},
		{"no audience", func(c *serviceJWTConfig) { c.Audience = "" }},
		{"no key at all", func(c *serviceJWTConfig) { c.PrivateKeyPEM = "" }},
		{"both key sources", func(c *serviceJWTConfig) { c.PrivateKeyFile = "/dev/null" }},
		{"not PEM", func(c *serviceJWTConfig) { c.PrivateKeyPEM = "hello" }},
		{"wrong curve", func(c *serviceJWTConfig) { c.PrivateKeyPEM = p384PEM }},
		{"lifetime above cap", func(c *serviceJWTConfig) { c.LifetimeSec = int(maxJWTLifetime/time.Second) + 1 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := base()
			tc.mangle(config)
			if _, err := newRequestSigner(config); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func TestNewRequestSignerDefaults(t *testing.T) {
	_, keyPEM := ecKeyPEM(t, elliptic.P256())
	signer, err := newRequestSigner(&serviceJWTConfig{
		PrivateKeyPEM: keyPEM, Kid: "k1", Issuer: "iss", Audience: "aud"})
	if err != nil {
		t.Fatal(err)
	}
	if signer.header != "Authorization" || signer.scheme != "Bearer" {
		t.Errorf("unexpected header/scheme %q %q", signer.header, signer.scheme)
	}
	if signer.lifetime != defaultJWTLifetime {
		t.Errorf("unexpected lifetime %v", signer.lifetime)
	}
}

func TestNewRequestSignerReadsKeyFile(t *testing.T) {
	_, keyPEM := ecKeyPEM(t, elliptic.P256())
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte(keyPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newRequestSigner(&serviceJWTConfig{
		PrivateKeyFile: path, Kid: "k1", Issuer: "iss", Audience: "aud"}); err != nil {
		t.Fatal(err)
	}
}

func TestSignBindsTokenToRequest(t *testing.T) {
	key, keyPEM := ecKeyPEM(t, elliptic.P256())
	signer, err := newRequestSigner(&serviceJWTConfig{
		PrivateKeyPEM: keyPEM, Kid: "k1", Issuer: "iss", Audience: "aud", LifetimeSec: 42})
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"endpoint":"auth"}`)
	tokenStr, err := signer.sign(http.MethodPost, "/some/path", body)
	if err != nil {
		t.Fatal(err)
	}

	claims := &bindingClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(*jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatal(err)
	}
	if kid, _ := token.Header["kid"].(string); kid != "k1" {
		t.Errorf("kid = %q, want k1", kid)
	}
	if claims.Method != http.MethodPost || claims.Path != "/some/path" {
		t.Errorf("binding = %q %q", claims.Method, claims.Path)
	}
	sum := sha256.Sum256(body)
	if claims.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("body_sha256 = %q", claims.BodySHA256)
	}
	if claims.Issuer != "iss" || len(claims.Audience) != 1 || claims.Audience[0] != "aud" {
		t.Errorf("iss/aud = %q %v", claims.Issuer, claims.Audience)
	}
	if claims.ID == "" {
		t.Error("jti is empty")
	}
	if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != 42*time.Second {
		t.Errorf("exp-iat = %v, want 42s", got)
	}
}

func TestSignIssuesUniqueJTI(t *testing.T) {
	_, keyPEM := ecKeyPEM(t, elliptic.P256())
	signer, err := newRequestSigner(&serviceJWTConfig{
		PrivateKeyPEM: keyPEM, Kid: "k1", Issuer: "iss", Audience: "aud"})
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		tokenStr, err := signer.sign(http.MethodPost, "/p", nil)
		if err != nil {
			t.Fatal(err)
		}
		claims := &bindingClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(tokenStr, claims); err != nil {
			t.Fatal(err)
		}
		if seen[claims.ID] {
			t.Fatalf("jti %q reused", claims.ID)
		}
		seen[claims.ID] = true
	}
}

// captureEndpoint stands in for the authentication service: it records what it was
// called with and answers with an empty successful response.
func captureEndpoint(t *testing.T, got *http.Request, body *[]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = *r.Clone(r.Context())
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		*body = buf
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCallEndpointUnsignedByDefault(t *testing.T) {
	var got http.Request
	var body []byte
	srv := captureEndpoint(t, &got, &body)

	a := &authenticator{name: "rest", serverUrl: srv.URL}
	if _, err := a.callEndpoint("auth", nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if h := got.Header.Get("Authorization"); h != "" {
		t.Errorf("unconfigured authenticator sent Authorization: %q", h)
	}
}

func TestCallEndpointSignsTheRequestItSends(t *testing.T) {
	key, keyPEM := ecKeyPEM(t, elliptic.P256())
	var got http.Request
	var body []byte
	srv := captureEndpoint(t, &got, &body)

	a := &authenticator{name: "rest", serverUrl: srv.URL + "/internal/", useSeparateEndpoints: true}
	var err error
	if a.signer, err = newRequestSigner(&serviceJWTConfig{
		PrivateKeyPEM: keyPEM, Kid: "k1", Issuer: "iss", Audience: "aud",
		Header: "X-Service-Token", Scheme: "SVC"}); err != nil {
		t.Fatal(err)
	}

	if _, err := a.callEndpoint("auth", nil, []byte("secret"), "1.2.3.4"); err != nil {
		t.Fatal(err)
	}

	header := got.Header.Get("X-Service-Token")
	if !strings.HasPrefix(header, "SVC ") {
		t.Fatalf("unexpected header value %q", header)
	}

	claims := &bindingClaims{}
	if _, err := jwt.ParseWithClaims(strings.TrimPrefix(header, "SVC "), claims,
		func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"})); err != nil {
		t.Fatal(err)
	}

	// The point of the binding is that the receiver can recompute it from the
	// request as delivered, so verify it against what the server actually got.
	if claims.Method != got.Method {
		t.Errorf("method claim %q, request %q", claims.Method, got.Method)
	}
	if claims.Path != got.URL.EscapedPath() {
		t.Errorf("path claim %q, request %q", claims.Path, got.URL.EscapedPath())
	}
	sum := sha256.Sum256(body)
	if claims.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("body_sha256 claim does not match the delivered body")
	}
	// And the delivered body is still the payload the authenticator meant to send.
	var payload request
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Endpoint != "auth" || payload.RemoteAddr != "1.2.3.4" {
		t.Errorf("unexpected payload %+v", payload)
	}
}

func TestInitAcceptsServiceJWTConfig(t *testing.T) {
	_, keyPEM := ecKeyPEM(t, elliptic.P256())
	jsconf, err := json.Marshal(map[string]any{
		"server_url": "http://localhost:1/",
		"service_jwt": map[string]any{
			"private_key_pem": keyPEM, "kid": "k1", "issuer": "iss", "audience": "aud",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	a := &authenticator{}
	if err := a.Init(jsconf, "rest"); err != nil {
		t.Fatal(err)
	}
	if a.signer == nil {
		t.Fatal("signer was not configured")
	}

	// A broken service_jwt block must stop the server rather than silently fall
	// back to unauthenticated calls.
	jsconf, err = json.Marshal(map[string]any{
		"server_url":  "http://localhost:1/",
		"service_jwt": map[string]any{"kid": "k1", "issuer": "iss", "audience": "aud"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&authenticator{}).Init(jsconf, "rest"); err == nil {
		t.Fatal("expected Init to fail on an invalid service_jwt block")
	}
}

func TestAuthorizeP2PUsesSignedPolicyRequest(t *testing.T) {
	key, keyPEM := ecKeyPEM(t, elliptic.P256())
	var got http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r.Clone(r.Context())
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"boolval":true}`))
	}))
	defer srv.Close()

	a := &authenticator{name: "basic", serverUrl: srv.URL + "/", useSeparateEndpoints: true}
	var err error
	a.signer, err = newRequestSigner(&serviceJWTConfig{
		PrivateKeyPEM: keyPEM, Kid: "k1", Issuer: "iss", Audience: "aud",
	})
	if err != nil {
		t.Fatal(err)
	}

	requester := types.ParseUserId("usrAAAAAAAAAAA")
	target := types.ParseUserId("usrAQAAAAAAAAA")
	allowed, err := a.AuthorizeP2P(requester, target, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("policy response was not returned")
	}
	if got.URL.Path != "/p2p" {
		t.Fatalf("path = %q, want /p2p", got.URL.Path)
	}

	var payload request
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Endpoint != "p2p" || payload.Name != "basic" || payload.P2P == nil {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if payload.P2P.Requester != requester.String() || payload.P2P.Target != target.String() {
		t.Fatalf("unexpected P2P IDs: %+v", payload.P2P)
	}
	if strings.HasPrefix(payload.P2P.Requester, "usr") || strings.HasPrefix(payload.P2P.Target, "usr") {
		t.Fatal("P2P policy request must contain provider UIDs, not Tinode topic names")
	}
	if payload.Secret != nil || payload.Record != nil {
		t.Fatal("P2P policy request must not reuse authentication credential fields")
	}

	header := strings.TrimPrefix(got.Header.Get("Authorization"), "Bearer ")
	claims := &bindingClaims{}
	if _, err := jwt.ParseWithClaims(header, claims,
		func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"})); err != nil {
		t.Fatal(err)
	}
	if claims.Path != got.URL.EscapedPath() || claims.Method != got.Method {
		t.Fatalf("request binding = %s %s", claims.Method, claims.Path)
	}
	sum := sha256.Sum256(body)
	if claims.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("body_sha256 does not cover the delivered policy request")
	}
}
