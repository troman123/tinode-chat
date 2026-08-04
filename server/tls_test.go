package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedCert writes a certificate and its key to dir, returning both paths.
func selfSignedCert(t *testing.T, dir, name string) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certFile = filepath.Join(dir, name+".crt")
	keyFile = filepath.Join(dir, name+".key")
	write := func(path, blockType string, bytes []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: bytes}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(certFile, "CERTIFICATE", der)
	write(keyFile, "PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func grpcTLSJSON(t *testing.T, config map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return json.RawMessage(raw)
}

func TestParseListenerTLSConfigAbsentOrDisabled(t *testing.T) {
	conf, err := parseListenerTLSConfig(nil, "grpc_tls")
	if err != nil || conf != nil {
		t.Fatalf("missing section: conf=%v err=%v", conf, err)
	}

	conf, err = parseListenerTLSConfig(grpcTLSJSON(t, map[string]any{"enabled": false}), "grpc_tls")
	if err != nil || conf != nil {
		t.Fatalf("disabled section: conf=%v err=%v", conf, err)
	}
}

func TestParseListenerTLSConfigClientAuth(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := selfSignedCert(t, dir, "server")
	caFile, _ := selfSignedCert(t, dir, "ca")

	base := func() map[string]any {
		return map[string]any{"enabled": true, "cert_file": certFile, "key_file": keyFile}
	}

	// No client CA: encryption only, client certificates are not asked for.
	conf, err := parseListenerTLSConfig(grpcTLSJSON(t, base()), "grpc_tls")
	if err != nil {
		t.Fatal(err)
	}
	if conf.ClientAuth != tls.NoClientCert || conf.ClientCAs != nil {
		t.Errorf("plain TLS: ClientAuth=%v ClientCAs=%v", conf.ClientAuth, conf.ClientCAs)
	}

	// Client CA alone: a presented certificate is verified, but is not mandatory.
	config := base()
	config["client_ca_file"] = caFile
	if conf, err = parseListenerTLSConfig(grpcTLSJSON(t, config), "grpc_tls"); err != nil {
		t.Fatal(err)
	}
	if conf.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth=%v, want VerifyClientCertIfGiven", conf.ClientAuth)
	}
	if conf.ClientCAs == nil {
		t.Error("ClientCAs was not populated")
	}

	// Both: mutual TLS.
	config["require_client_cert"] = true
	if conf, err = parseListenerTLSConfig(grpcTLSJSON(t, config), "grpc_tls"); err != nil {
		t.Fatal(err)
	}
	if conf.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth=%v, want RequireAndVerifyClientCert", conf.ClientAuth)
	}
}

func TestParseListenerTLSConfigRejectsUnusableClientAuth(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := selfSignedCert(t, dir, "server")

	// Requiring a client certificate with nothing to verify it against would
	// accept any self-signed certificate, i.e. authenticate nobody.
	config := map[string]any{
		"enabled": true, "cert_file": certFile, "key_file": keyFile,
		"require_client_cert": true,
	}
	if _, err := parseListenerTLSConfig(grpcTLSJSON(t, config), "grpc_tls"); err == nil {
		t.Error("require_client_cert without client_ca_file was accepted")
	}

	// An unreadable or non-certificate CA file must fail loudly rather than leave
	// the listener silently unauthenticated.
	notACA := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(notACA, []byte("not a certificate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config["client_ca_file"] = notACA
	if _, err := parseListenerTLSConfig(grpcTLSJSON(t, config), "grpc_tls"); err == nil {
		t.Error("a client_ca_file without certificates was accepted")
	}

	config["client_ca_file"] = filepath.Join(dir, "does-not-exist.pem")
	if _, err := parseListenerTLSConfig(grpcTLSJSON(t, config), "grpc_tls"); err == nil {
		t.Error("a missing client_ca_file was accepted")
	}
}

func TestParseTLSConfigUnchangedForHTTPListener(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := selfSignedCert(t, dir, "server")

	if conf, err := parseTLSConfig(false, nil); err != nil || conf != nil {
		t.Fatalf("TLS off: conf=%v err=%v", conf, err)
	}

	globals.tlsStrictMaxAge = ""
	globals.tlsRedirectHTTP = ""
	conf, err := parseTLSConfig(true, grpcTLSJSON(t, map[string]any{
		"cert_file": certFile, "key_file": keyFile,
		"strict_max_age": 31536000, "http_redirect": ":80",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Certificates) != 1 {
		t.Error("no certificate was loaded")
	}
	if globals.tlsStrictMaxAge != "31536000" || globals.tlsRedirectHTTP != ":80" {
		t.Errorf("HTTP listener settings not applied: %q %q",
			globals.tlsStrictMaxAge, globals.tlsRedirectHTTP)
	}
	// The public HTTP listener must not start demanding client certificates just
	// because the option now exists.
	if conf.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth=%v, want NoClientCert", conf.ClientAuth)
	}
}
