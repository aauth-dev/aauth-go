package aauth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
)

// Server-signed requests (draft -11 §11.3.2): a PS, AS, AP, or resource
// making a signed AAuth request in its own right — a PS-to-AS token request
// (§9.1.1), a revocation (§11.12) — MUST use the jwks_uri Signature-Key
// scheme (signature-key §3.6). id is the server's issuer as published in
// its metadata and dwk that metadata document's well-known name; the
// recipient discovers the key at {id}/.well-known/{dwk} → jwks_uri → kid,
// and id becomes the caller's identity.

// ServerSigner signs requests a server makes in its own right.
type ServerSigner struct {
	// Issuer is the server's issuer (its server identifier, §11.1.1),
	// sent as the id parameter.
	Issuer string
	// DWK is the server's metadata document name: WellKnownPerson,
	// WellKnownAccess, WellKnownAgent, or WellKnownResource.
	DWK string
	// Kid identifies Key in the JWKS at the server's jwks_uri. That JWKS
	// entry MUST carry a fully-specified alg (§11.4).
	Kid string
	// Key is the server's signing key.
	Key crypto.Signer
}

// AttachSignatureKeyJWKSURI sets the Signature-Key header for the jwks_uri
// scheme under the default label:
//
//	sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="key-1"
func AttachSignatureKeyJWKSURI(req *http.Request, id, dwk, kid string) {
	req.Header.Set(HeaderSignatureKey, DefaultSignatureLabel+"=jwks_uri;id="+sfString(id)+";dwk="+sfString(dwk)+";kid="+sfString(kid))
}

// SignRequest attaches the jwks_uri Signature-Key and signs req (see the
// package-level SignRequest for covered components).
func (s ServerSigner) SignRequest(req *http.Request) error {
	if s.Issuer == "" || s.DWK == "" || s.Kid == "" {
		return fmt.Errorf("aauth: ServerSigner requires Issuer, DWK, and Kid")
	}
	AttachSignatureKeyJWKSURI(req, s.Issuer, s.DWK, s.Kid)
	return SignRequest(req, s.Key, "")
}

// ServerCaller identifies the server that signed a request under the
// jwks_uri scheme.
type ServerCaller struct {
	// ID is the caller's identity: its issuer, the iss of every token it
	// mints.
	ID string
	// DWK is the metadata document its key was discovered through, which
	// names its role (e.g. aauth-person.json for a PS).
	DWK string
	// Kid is the key that signed the request.
	Kid string
}

// VerifyServerOptions tunes VerifyServerRequest.
type VerifyServerOptions struct {
	// Resolver discovers the caller's key from (id, dwk, kid); nil uses a
	// JWKSResolver with DefaultJWKSCache. Discovery verifies that the
	// metadata issuer equals id (issuer_missing / issuer_mismatch).
	Resolver KeyResolver
	// DWKs, when non-empty, restricts the metadata documents (roles)
	// accepted, e.g. []string{WellKnownPerson} at an AS token endpoint.
	DWKs []string
	// TrustSigner, when set, is consulted before any fetch; returning
	// false rejects the caller with invalid_key. Verifiers SHOULD check id
	// against expected origins (signature-key §7.3); a verifier that
	// accepts unknown signers obtains an origin-bound pseudonym, not an
	// authorized identity.
	TrustSigner func(id, dwk string) bool
	// Signature tunes HTTP message-signature verification. PS, AS, and
	// revocation endpoints should set RequireBodyCoverage (§11.3.3.1).
	Signature RequestVerifyOptions
}

// VerifyServerRequest authenticates a request signed under the jwks_uri
// scheme (draft -11 §11.3.2; signature-key §3.6): it parses the
// Signature-Key member for the default label, requires the jwks_uri scheme
// with id, dwk, and kid, discovers the key, and verifies the HTTP message
// signature. Errors classify with [SignatureErrorFor]; a jwt (agent) or
// other scheme is unsupported_scheme with Accept-Signature-Scheme: jwks_uri.
func VerifyServerRequest(ctx context.Context, req *http.Request, opts VerifyServerOptions) (*ServerCaller, error) {
	sk, err := ParseSignatureKeyMember(req, DefaultSignatureLabel)
	if err != nil {
		return nil, err
	}
	if sk.Scheme != SchemeJWKSURI {
		return nil, &UnsupportedSchemeError{Scheme: sk.Scheme, Accepted: []string{SchemeJWKSURI}}
	}
	caller := &ServerCaller{ID: sk.Params["id"], DWK: sk.Params["dwk"], Kid: sk.Params["kid"]}
	if caller.ID == "" || caller.DWK == "" || caller.Kid == "" {
		return nil, fmt.Errorf("%w: jwks_uri scheme requires id, dwk, and kid", ErrBadSigKey)
	}
	if len(opts.DWKs) > 0 && !contains(opts.DWKs, caller.DWK) {
		return nil, fmt.Errorf("%w: signer role %q not accepted here", ErrInvalidKey, caller.DWK)
	}
	if opts.TrustSigner != nil && !opts.TrustSigner(caller.ID, caller.DWK) {
		return nil, fmt.Errorf("%w: untrusted signer %q", ErrInvalidKey, caller.ID)
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = JWKSResolver{}
	}
	pub, err := resolver.ResolveKey(ctx, caller.ID, caller.DWK, caller.Kid, nil)
	if err != nil {
		return nil, err
	}
	err = VerifyRequestWithOptions(req, pub, opts.Signature)
	if err != nil && isSignatureMismatch(err) {
		// The issuer may have re-keyed under the same kid (signature-key
		// §7.2): refresh once, subject to the resolver's fetch floor.
		if rr, ok := resolver.(KeyRefresher); ok {
			fresh, rerr := rr.RefreshKey(ctx, caller.ID, caller.DWK, caller.Kid, nil)
			if rerr != nil {
				return nil, rerr
			}
			err = VerifyRequestWithOptions(req, fresh, opts.Signature)
		}
	}
	if err != nil {
		return nil, err
	}
	return caller, nil
}

// isSignatureMismatch reports whether err is a failure of the
// cryptographic check itself, as opposed to a coverage or freshness failure
// that a different key could not fix.
func isSignatureMismatch(err error) bool { return errors.Is(err, errSignatureMismatch) }

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
