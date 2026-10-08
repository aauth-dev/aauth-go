package personserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
)

// DirectedSubject derives the person's directed identifier at resource
// (draft -11 §14.1, §10.1.1.2): a keyed HMAC-SHA-256 over the resource and
// the person, base64url-encoded without padding. Each resource sees a
// different value for the same person, the value is the same in every
// person token and auth token for that resource, and it does not vary with
// the agent or its key. key is the PS's secret derivation key; anyone
// without it cannot correlate values across resources.
func DirectedSubject(key []byte, person, resource string) string {
	m := hmac.New(sha256.New, key)
	// Length-prefix each field so distinct pairs never share an input.
	for _, f := range []string{resource, person} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		m.Write(n[:])
		m.Write([]byte(f))
	}
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

type subjectDeriver struct{ key []byte }

func (d subjectDeriver) derive(person, resource string) string {
	return DirectedSubject(d.key, person, resource)
}
