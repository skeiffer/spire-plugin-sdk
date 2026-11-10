package x509svidissuerv1

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestContractShape(t *testing.T) {
	service := File_spire_plugin_server_x509svidissuer_v1_x509svidissuer_proto.Services().ByName("X509SVIDIssuer")
	if service == nil {
		t.Fatal("X509SVIDIssuer service is missing")
	}
	issue := service.Methods().ByName("IssueX509SVID")
	if issue == nil || issue.IsStreamingClient() || issue.IsStreamingServer() {
		t.Fatal("IssueX509SVID must be unary")
	}
	subscribe := service.Methods().ByName("SubscribeAuthoritySnapshots")
	if subscribe == nil || subscribe.IsStreamingClient() || !subscribe.IsStreamingServer() {
		t.Fatal("SubscribeAuthoritySnapshots must be server streaming")
	}

	requireField(t, issue.Input(), "csr", 1)
	requireField(t, issue.Input(), "profile", 2)
	requireField(t, issue.Input(), "authority_version", 3)
	requireField(t, issue.Output(), "leaf_certificate", 1)
	requireField(t, issue.Output(), "intermediates", 2)
	requireField(t, issue.Output(), "authority_version", 3)

	profile := File_spire_plugin_server_x509svidissuer_v1_x509svidissuer_proto.Messages().ByName("X509SVIDProfile")
	requireField(t, profile, "public_key", 3)
	requireField(t, profile, "not_before", 9)
	requireField(t, profile, "not_after", 10)

	snapshot := File_spire_plugin_server_x509svidissuer_v1_x509svidissuer_proto.Messages().ByName("AuthoritySnapshot")
	requireField(t, snapshot, "authority_version", 1)
	requireField(t, snapshot, "authority_chains", 2)
}

func TestCSRWireCompatibilityAndJSONName(t *testing.T) {
	// Field 1 encoded by the preceding proof_csr contract.
	legacyWire := []byte{0x0a, 0x03, 'c', 's', 'r'}
	var request IssueX509SVIDRequest
	if err := proto.Unmarshal(legacyWire, &request); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request.GetCsr(), []byte("csr")) {
		t.Fatalf("legacy CSR was not preserved: %q", request.GetCsr())
	}
	wire, err := proto.Marshal(&request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, legacyWire) {
		t.Fatalf("CSR wire encoding changed: %x", wire)
	}

	jsonBytes, err := protojson.Marshal(&request)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal(jsonBytes, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || fields["csr"] != "Y3Ny" {
		t.Fatalf("unexpected CSR JSON encoding: %s", jsonBytes)
	}
}

func TestCSRUsesAuthoritativeProfile(t *testing.T) {
	proofKey := newTestKey(t)
	profileKey, err := x509.MarshalPKIXPublicKey(proofKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	csr := newCSR(t, proofKey, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "untrusted CSR subject"},
		DNSNames: []string{"untrusted.example"},
	})

	request := &IssueX509SVIDRequest{
		Csr:     csr,
		Profile: &X509SVIDProfile{PublicKey: profileKey},
	}
	if err := validateCSR(request); err != nil {
		t.Fatalf("valid proof CSR rejected: %v", err)
	}

	otherKey := newTestKey(t)
	otherPublicKey, err := x509.MarshalPKIXPublicKey(otherKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	request.Profile.PublicKey = otherPublicKey
	if err := validateCSR(request); !errors.Is(err, errProofKeyMismatch) {
		t.Fatalf("expected proof key mismatch, got %v", err)
	}

	malformed := append([]byte(nil), csr...)
	malformed[len(malformed)-1] ^= 0xff
	request.Csr = malformed
	request.Profile.PublicKey = profileKey
	if err := validateCSR(request); err == nil {
		t.Fatal("expected malformed proof signature to be rejected")
	}
}

func TestAuthorityVersionsAreContentImmutable(t *testing.T) {
	registry := newAuthorityRegistry()
	versionOne := &AuthoritySnapshot{
		AuthorityVersion: "authority-1",
		AuthorityChains: []*AuthorityChain{{
			Root:          []byte("root-1"),
			Intermediates: [][]byte{[]byte("intermediate-1")},
		}},
	}

	if err := registry.publish(versionOne); err != nil {
		t.Fatalf("initial snapshot rejected: %v", err)
	}
	if err := registry.publish(versionOne); err != nil {
		t.Fatalf("idempotent snapshot rejected: %v", err)
	}

	changed := &AuthoritySnapshot{
		AuthorityVersion: versionOne.AuthorityVersion,
		AuthorityChains:  []*AuthorityChain{{Root: []byte("different-root")}},
	}
	if err := registry.publish(changed); !errors.Is(err, errAuthorityVersionReused) {
		t.Fatalf("expected immutable version rejection, got %v", err)
	}

	changed.AuthorityVersion = "authority-2"
	if err := registry.publish(changed); err != nil {
		t.Fatalf("new immutable version rejected: %v", err)
	}

	if err := validateAuthorityVersion("authority-2", "authority-1"); !errors.Is(err, errAuthorityVersionMismatch) {
		t.Fatalf("expected issuance authority version mismatch, got %v", err)
	}
	if err := validateAuthorityVersion("authority-2", "authority-2"); err != nil {
		t.Fatalf("matching issuance authority version rejected: %v", err)
	}
}

var (
	errProofKeyMismatch         = errors.New("proof CSR public key does not match profile")
	errAuthorityVersionReused   = errors.New("authority version reused with different content")
	errAuthorityVersionMismatch = errors.New("issuance authority version does not match request")
)

func requireField(t *testing.T, message protoreflect.MessageDescriptor, name protoreflect.Name, number protoreflect.FieldNumber) {
	t.Helper()
	if message == nil {
		t.Fatalf("message containing field %q is missing", name)
	}
	field := message.Fields().ByName(name)
	if field == nil {
		t.Fatalf("%s.%s is missing", message.Name(), name)
	}
	if field.Number() != number {
		t.Fatalf("%s.%s has field number %d, expected %d", message.Name(), name, field.Number(), number)
	}
}

func validateCSR(request *IssueX509SVIDRequest) error {
	csr, err := x509.ParseCertificateRequest(request.GetCsr())
	if err != nil {
		return err
	}
	if err := csr.CheckSignature(); err != nil {
		return err
	}
	csrPublicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(csrPublicKey, request.GetProfile().GetPublicKey()) {
		return errProofKeyMismatch
	}
	return nil
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newCSR(t *testing.T, signer crypto.Signer, template *x509.CertificateRequest) []byte {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

type authorityRegistry map[string][]byte

func newAuthorityRegistry() authorityRegistry {
	return make(authorityRegistry)
}

func (r authorityRegistry) publish(snapshot *AuthoritySnapshot) error {
	var canonical bytes.Buffer
	writeLength(&canonical, len(snapshot.GetAuthorityChains()))
	for _, chain := range snapshot.GetAuthorityChains() {
		writeLengthPrefixed(&canonical, chain.GetRoot())
		writeLength(&canonical, len(chain.GetIntermediates()))
		for _, intermediate := range chain.GetIntermediates() {
			writeLengthPrefixed(&canonical, intermediate)
		}
	}

	content := canonical.Bytes()
	if previous, ok := r[snapshot.GetAuthorityVersion()]; ok && !bytes.Equal(previous, content) {
		return errAuthorityVersionReused
	}
	r[snapshot.GetAuthorityVersion()] = append([]byte(nil), content...)
	return nil
}

func writeLengthPrefixed(out *bytes.Buffer, value []byte) {
	writeLength(out, len(value))
	out.Write(value)
}

func writeLength(out *bytes.Buffer, value int) {
	length := uint64(value)
	for length >= 0x80 {
		out.WriteByte(byte(length&0x7f) | 0x80)
		length >>= 7
	}
	out.WriteByte(byte(length))
}

func validateAuthorityVersion(requested, returned string) error {
	if requested != returned {
		return errAuthorityVersionMismatch
	}
	return nil
}
