// Package interactioncode generates and canonicalizes AAuth interaction
// codes (draft-hardt-oauth-aauth-protocol-11; format per the interaction-code
// requirements: unambiguous alphabet, minimum entropy). Mirrors
// @aauth/interaction-code from the reference TypeScript packages.
//
// Codes are 8 characters of Crockford base32 (40 bits of entropy) rendered
// as XXXX-XXXX. The Crockford alphabet excludes I, L, O, U; canonicalization
// folds the lookalikes a user might type (i/l→1, o→0) and uppercases.
package interactioncode

import (
	"crypto/rand"
	"fmt"
	"strings"
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Generate returns a fresh interaction code in XXXX-XXXX form (40 bits).
func Generate() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("interactioncode: %w", err)
	}
	out := make([]byte, 9)
	for i, v := range b {
		pos := i
		if i >= 4 {
			pos = i + 1
		}
		out[pos] = alphabet[int(v)%len(alphabet)]
	}
	out[4] = '-'
	return string(out), nil
}

// Canonicalize normalizes user input for comparison: uppercase, strip
// separators/whitespace, fold I/L→1 and O→0, re-hyphenate as XXXX-XXXX.
func Canonicalize(code string) (string, error) {
	var sb strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		case 'U':
			return "", fmt.Errorf("interactioncode: invalid character %q", r)
		}
		if !strings.ContainsRune(alphabet, r) {
			return "", fmt.Errorf("interactioncode: invalid character %q", r)
		}
		sb.WriteRune(r)
	}
	s := sb.String()
	if len(s) != 8 {
		return "", fmt.Errorf("interactioncode: expected 8 symbols, got %d", len(s))
	}
	return s[:4] + "-" + s[4:], nil
}
