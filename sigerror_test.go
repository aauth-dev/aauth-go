package aauth

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSignatureErrorRoundTrip(t *testing.T) {
	e := SignatureError{Code: SigErrUnsupportedAlgorithm, Params: map[string]string{
		"supported_algorithms": `("ed25519")`,
	}}
	parsed, err := ParseSignatureError(e.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Code != e.Code || parsed.Params["supported_algorithms"] != `("ed25519")` {
		t.Fatalf("parsed %+v", parsed)
	}
	// Spec example.
	parsed, err = ParseSignatureError(`error=unsupported_algorithm, supported_algorithms=("ed25519" "ecdsa-p256-sha256")`)
	if err != nil || parsed.Code != SigErrUnsupportedAlgorithm {
		t.Fatalf("%+v, %v", parsed, err)
	}
	// Absent header → nil, no error.
	if p, err := ParseSignatureError(""); p != nil || err != nil {
		t.Fatalf("empty: %+v, %v", p, err)
	}
	// Missing required member.
	if _, err := ParseSignatureError("supported_algorithms=(\"x\")"); err == nil {
		t.Fatal("missing error member accepted")
	}
}

func TestWriteSignatureError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteSignatureError(rec, 400, SignatureError{Code: SigErrInvalidSignature}, "signature base mismatch")
	res := rec.Result()
	defer closeBody(res.Body)

	se, err := SignatureErrorFromResponse(res)
	if err != nil || se == nil || se.Code != SigErrInvalidSignature {
		t.Fatalf("header: %+v, %v", se, err)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content-type %q", ct)
	}
	var pd map[string]any
	if err := json.NewDecoder(res.Body).Decode(&pd); err != nil {
		t.Fatal(err)
	}
	if typ, _ := pd["type"].(string); !strings.HasSuffix(typ, "sig-error:invalid_signature") {
		t.Fatalf("problem type %q", pd["type"])
	}
	if pd["status"].(float64) != 400 {
		t.Fatalf("problem status %v", pd["status"])
	}
}
