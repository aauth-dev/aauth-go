package aauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/dunglas/httpsfv"
)

// Signature-Error (signature-key §5): the machine-readable channel for
// signature-related rejections. The header is authoritative; the RFC 9457
// problem+json body is for humans and MAY duplicate header members.
//
// AAuth answers every signature failure with 401 (draft -11 §11.3.4,
// Appendix C.2.5). A 403 denies access after the signature verified and
// MUST NOT carry Signature-Error, Accept-Signature-Scheme, or
// Accept-Signature-Alg (signature-key §5.3).

// Signature-Error codes (signature-key §5.4; Signature Error Code registry,
// §9.4.1).
const (
	SigErrUnsupportedAlgorithm = "unsupported_algorithm" // §5.4.1: alg absent, polymorphic, or not implemented
	SigErrUnsupportedScheme    = "unsupported_scheme"    // §5.4.2: Signature-Key scheme not implemented
	SigErrCacheMiss            = "cache_miss"            // §5.4.3: cached-scheme identifier not resolved
	SigErrInvalidSignature     = "invalid_signature"     // §5.4.4: missing/malformed/stale/failed signature
	SigErrInvalidInput         = "invalid_input"         // §5.4.5: required components not covered
	SigErrInvalidRequest       = "invalid_request"       // §5.4.6: malformed request, unrelated to the signature
	SigErrInvalidKey           = "invalid_key"           // §5.4.7: key unparsable, or kty/crv disagree with alg
	SigErrUnknownKey           = "unknown_key"           // §5.4.8: no key with the kid at the jwks_uri
	SigErrIssuerMissing        = "issuer_missing"        // §5.4.9: discovered metadata lacks issuer
	SigErrIssuerMismatch       = "issuer_mismatch"       // §5.4.10: metadata issuer differs from the identity
	SigErrInvalidJWT           = "invalid_jwt"           // §5.4.11: JWT malformed or its signature failed
	SigErrExpiredJWT           = "expired_jwt"           // §5.4.12: JWT exp in the past
	SigErrRevokedJWT           = "revoked_jwt"           // §5.4.13: JWT withdrawn by its issuer
	SigErrClockSkew            = "clock_skew"            // §5.4.14: created or iat ahead of the verifier's clock
)

// Response header names (signature-key §4).
const (
	HeaderAcceptSignatureScheme = "Accept-Signature-Scheme"
	HeaderAcceptSignatureAlg    = "Accept-Signature-Alg"
)

// AcceptedSignatureSchemes returns the Signature-Key schemes this
// implementation verifies on AAuth requests, in preference order.
func AcceptedSignatureSchemes() []string { return []string{SchemeJWT} }

// AcceptedSignatureAlgs returns the fully-specified algorithms this
// implementation verifies, in preference order.
func AcceptedSignatureAlgs() []string { return acceptedJWSAlgs() }

// SignatureError is a parsed Signature-Error header: a Structured Field
// Dictionary (RFC 9651 §3.2) whose error member is a Token.
type SignatureError struct {
	// Code is the required error member.
	Code string
	// RequiredInput accompanies invalid_input: the covered components the
	// server requires (an Inner List of Strings).
	RequiredInput []string
	// Params carries any other members, each in its RFC 9651 serialized
	// form (a token, a quoted string, an inner list, ...). Unknown members
	// are preserved; recipients ignore what they don't know.
	Params map[string]string
}

// Error implements error.
func (e *SignatureError) Error() string {
	return "aauth: signature error: " + e.Code
}

// String renders the header value as a Structured Field Dictionary:
// `error=<code>[, required_input=("..." ...)][, k=v ...]`, with any extra
// members in key order.
func (e SignatureError) String() string {
	var b strings.Builder
	b.WriteString("error=")
	b.WriteString(e.Code)
	if len(e.RequiredInput) > 0 {
		b.WriteString(", required_input=(")
		for i, c := range e.RequiredInput {
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(sfString(c))
		}
		b.WriteByte(')')
	}
	keys := make([]string, 0, len(e.Params))
	for k := range e.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, ", %s=%s", k, e.Params[k])
	}
	return b.String()
}

// sfString serializes s as an RFC 9651 String (§4.1.6): quoted, with " and \
// escaped. Characters outside printable ASCII are dropped, since a String
// cannot carry them.
func sfString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r >= 0x20 && r <= 0x7e:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ParseSignatureError parses a Signature-Error header value as a
// Structured Field Dictionary. Returns nil if the value is empty (no
// signature error present).
func ParseSignatureError(v string) (*SignatureError, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	dict, err := httpsfv.UnmarshalDictionary([]string{v})
	if err != nil {
		return nil, fmt.Errorf("aauth: malformed Signature-Error: %w", err)
	}
	e := &SignatureError{Params: map[string]string{}}
	for _, name := range dict.Names() {
		m, _ := dict.Get(name)
		switch name {
		case "error":
			it, ok := m.(httpsfv.Item)
			if !ok {
				return nil, fmt.Errorf("aauth: Signature-Error error member is not an item")
			}
			switch code := it.Value.(type) {
			case httpsfv.Token:
				e.Code = string(code)
			case string: // tolerated: a quoted code
				e.Code = code
			default:
				return nil, fmt.Errorf("aauth: Signature-Error error member is not a token")
			}
		case "required_input":
			il, ok := m.(httpsfv.InnerList)
			if !ok {
				return nil, fmt.Errorf("aauth: Signature-Error required_input is not an inner list")
			}
			for _, it := range il.Items {
				s, ok := it.Value.(string)
				if !ok {
					return nil, fmt.Errorf("aauth: Signature-Error required_input member is not a string")
				}
				e.RequiredInput = append(e.RequiredInput, s)
			}
		default:
			d := httpsfv.NewDictionary()
			d.Add(name, m)
			s, err := httpsfv.Marshal(d)
			if err != nil {
				return nil, fmt.Errorf("aauth: Signature-Error member %q: %w", name, err)
			}
			if val, ok := strings.CutPrefix(s, name+"="); ok {
				e.Params[name] = val
			} else {
				e.Params[name] = "?1" // a bare key is Boolean true
			}
		}
	}
	if e.Code == "" {
		return nil, fmt.Errorf("aauth: Signature-Error missing required error member")
	}
	return e, nil
}

// SignatureErrorFromResponse extracts the Signature-Error from a response,
// or nil when absent.
func SignatureErrorFromResponse(res *http.Response) (*SignatureError, error) {
	return ParseSignatureError(res.Header.Get(HeaderSignatureError))
}

// AcceptSignatureFromResponse returns the Accept-Signature-Scheme and
// Accept-Signature-Alg lists (signature-key §4) from a response; either may
// be empty. Tokens are returned verbatim (alg case is significant) and
// members that are not tokens are skipped (clients MUST ignore what they do
// not recognize, §4.1).
func AcceptSignatureFromResponse(res *http.Response) (schemes, algs []string, err error) {
	if schemes, err = parseTokenList(res.Header.Values(HeaderAcceptSignatureScheme)); err != nil {
		return nil, nil, fmt.Errorf("aauth: %s: %w", HeaderAcceptSignatureScheme, err)
	}
	if algs, err = parseTokenList(res.Header.Values(HeaderAcceptSignatureAlg)); err != nil {
		return nil, nil, fmt.Errorf("aauth: %s: %w", HeaderAcceptSignatureAlg, err)
	}
	return schemes, algs, nil
}

// parseTokenList parses a Structured Field List of Tokens.
func parseTokenList(vals []string) ([]string, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	l, err := httpsfv.UnmarshalList(vals)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range l {
		if it, ok := m.(httpsfv.Item); ok {
			if tok, ok := it.Value.(httpsfv.Token); ok {
				out = append(out, string(tok))
			}
		}
	}
	return out, nil
}

// SignatureErrorFor classifies a verification error from this package as a
// Signature-Error (draft -11 §11.3.4; signature-key §5.4). ok is false when
// err is not a signature or credential failure (for example a network error
// fetching an issuer's keys), leaving the response to the caller.
func SignatureErrorFor(err error) (e SignatureError, ok bool) {
	var mce *MissingComponentsError
	switch {
	case err == nil:
		return SignatureError{}, false
	case errors.As(err, &mce):
		return SignatureError{Code: SigErrInvalidInput, RequiredInput: mce.Required}, true
	case errors.Is(err, ErrClockSkew):
		return SignatureError{Code: SigErrClockSkew}, true
	case errors.Is(err, ErrUnsupportedScheme):
		return SignatureError{Code: SigErrUnsupportedScheme}, true
	case errors.Is(err, ErrUnsupportedAlgorithm):
		return SignatureError{Code: SigErrUnsupportedAlgorithm}, true
	case errors.Is(err, ErrInvalidKey):
		return SignatureError{Code: SigErrInvalidKey}, true
	case errors.Is(err, ErrUnknownKey):
		return SignatureError{Code: SigErrUnknownKey}, true
	case errors.Is(err, ErrIssuerMissing):
		return SignatureError{Code: SigErrIssuerMissing}, true
	case errors.Is(err, ErrIssuerMismatch):
		return SignatureError{Code: SigErrIssuerMismatch}, true
	case errors.Is(err, ErrRevoked):
		return SignatureError{Code: SigErrRevokedJWT}, true
	case errors.Is(err, ErrExpired):
		return SignatureError{Code: SigErrExpiredJWT}, true
	case errors.Is(err, ErrInvalidToken), errors.Is(err, ErrWrongTokenType), errors.Is(err, ErrMissingClaim):
		return SignatureError{Code: SigErrInvalidJWT}, true
	case errors.Is(err, ErrSignatureInvalid), errors.Is(err, ErrMissingSigKey), errors.Is(err, ErrBadSigKey):
		return SignatureError{Code: SigErrInvalidSignature}, true
	}
	return SignatureError{}, false
}

// problemDetails is the RFC 9457 body accompanying a Signature-Error.
type problemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title,omitempty"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// WriteSignatureError writes a 401 response (draft -11 §11.3.4: every
// signature failure is 401) carrying the Signature-Error header and an
// RFC 9457 problem+json body whose type is urn:ietf:params:sig-error:<code>.
// For unsupported_scheme and unsupported_algorithm it also names what would
// succeed, in Accept-Signature-Scheme or Accept-Signature-Alg
// (signature-key §4.4).
//
// Policy denials after successful verification are NOT signature errors —
// return a plain 403 without this header (signature-key §5.3).
func WriteSignatureError(w http.ResponseWriter, e SignatureError, detail string) {
	h := w.Header()
	h.Set(HeaderSignatureError, e.String())
	switch e.Code {
	case SigErrUnsupportedScheme:
		h.Set(HeaderAcceptSignatureScheme, strings.Join(AcceptedSignatureSchemes(), ", "))
	case SigErrUnsupportedAlgorithm:
		h.Set(HeaderAcceptSignatureAlg, strings.Join(AcceptedSignatureAlgs(), ", "))
	}
	h.Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusUnauthorized)
	// The status and headers are already sent; a body write error cannot
	// change the response and there is no caller to report it to.
	_ = json.NewEncoder(w).Encode(problemDetails{
		Type:   "urn:ietf:params:sig-error:" + e.Code,
		Title:  strings.ReplaceAll(e.Code, "_", " "),
		Status: http.StatusUnauthorized,
		Detail: detail,
	})
}

// WriteSignatureFailure classifies err with [SignatureErrorFor] and writes
// the 401 Signature-Error response. An error that is not classified (such
// as a failure to reach an issuer's metadata) is reported as
// invalid_signature, since the request could not be authenticated.
func WriteSignatureFailure(w http.ResponseWriter, err error) {
	e, ok := SignatureErrorFor(err)
	if !ok {
		e = SignatureError{Code: SigErrInvalidSignature}
	}
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	WriteSignatureError(w, e, detail)
}
