package sandbox

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/interactioncode"
)

// resource is a demo resource serving every access mode on one origin:
//
//   - /api/documents serves a request presenting an agent token (agent
//     identity), a person token (person identity), or an auth token
//     (PS authorization, or federated authorization when audience is an
//     access server);
//   - /api/data manages authorization itself (resource-managed access):
//     it asks the person through an interaction, then issues an
//     AAuth-Access session token;
//   - /authorize is the authorization endpoint, answering with a resource
//     token addressed to audience.
type resource struct {
	sb       *Sandbox
	url      string
	audience string // the PS (three-party) or the AS (four-party)
	key      crypto.Signer
	jwk      aauth.JWK
	verify   aauth.TokenVerifyOptions

	mu       sync.Mutex
	pending  map[string]*interaction // by pending ID
	sessions map[string]string       // session token → agent key thumbprint
}

// interaction is a resource-managed request waiting for the person.
type interaction struct {
	code     string
	agentJKT string
	session  string // set once the person approves
}

var documentsBody = map[string]any{"documents": []map[string]string{
	{"id": "doc-1", "title": "Q3 planning"},
	{"id": "doc-2", "title": "Team offsite"},
}}

var dataBody = map[string]any{"items": []map[string]any{{"id": 1, "value": "example"}}}

func (s *Sandbox) newResource(role, audience string) (*resource, error) {
	key, err := loadOrCreateKey(s.cfg.StateDir, role)
	if err != nil {
		return nil, err
	}
	jwk, err := aauth.NewJWK(key.Public())
	if err != nil {
		return nil, err
	}
	return &resource{
		sb: s, url: s.cfg.URL(role), audience: audience, key: key, jwk: jwk,
		verify:   aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(s.Client(role))},
		pending:  map[string]*interaction{},
		sessions: map[string]string{},
	}, nil
}

func (rs *resource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch p := r.URL.Path; {
	case p == "/.well-known/"+aauth.WellKnownResource:
		writeJSON(w, http.StatusOK, aauth.ResourceMetadata{
			ServerMetadata:        aauth.ServerMetadata{Issuer: rs.url, JWKSURI: rs.url + PathJWKS},
			AccessMode:            aauth.AccessModeAuthToken,
			AuthorizationEndpoint: rs.url + "/authorize",
		})
	case p == PathJWKS:
		w.Header().Set("Cache-Control", "max-age=300")
		writeJSON(w, http.StatusOK, aauth.JWKS{Keys: []aauth.JWK{rs.jwk}})
	case p == "/authorize":
		rs.authorizationEndpoint().ServeHTTP(w, r)
	case p == "/api/documents":
		rs.serveDocuments(w, r)
	case p == "/api/data":
		rs.serveData(w, r)
	case strings.HasPrefix(p, PathPending):
		rs.servePending(w, r)
	case p == PathInteraction:
		rs.serveInteractionPage(w, r)
	case p == PathApprove:
		rs.serveApprove(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (rs *resource) authorizationEndpoint() http.Handler {
	return &aauth.AuthorizationHandler{
		Resource: rs.url,
		Verify:   rs.verify,
		Decide: func(_ context.Context, _ *http.Request, person *aauth.PersonClaims, ar aauth.AuthorizeRequest) (aauth.AuthorizeDecision, error) {
			if ar.Scope == "" {
				return aauth.AuthorizeDecision{}, &aauth.ProblemError{Status: http.StatusBadRequest, Code: aauth.ErrCodeInvalidScope, Detail: "scope is required"}
			}
			for _, sc := range strings.Fields(ar.Scope) {
				if !scopes[sc] {
					return aauth.AuthorizeDecision{}, &aauth.ProblemError{Status: http.StatusBadRequest, Code: aauth.ErrCodeInvalidScope, Detail: "scope " + sc + " is not offered"}
				}
			}
			rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{
				Resource: rs.url, Audience: rs.audience, Scope: ar.Scope,
			}, person, rs.key, rs.jwk.Kid)
			return aauth.AuthorizeDecision{ResourceToken: rt}, err
		},
	}
}

// serveDocuments serves whichever token the request presents.
func (rs *resource) serveDocuments(w http.ResponseWriter, r *http.Request) {
	tok, err := aauth.ParseSignatureKey(r)
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	typ, err := aauth.TokenType(tok)
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	switch typ {
	case aauth.TypAgent:
		if _, err := aauth.VerifyAndExtractAgent(r.Context(), r, aauth.VerifyAgentTokenOptions{Resolver: rs.verify.Resolver}); err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
	case aauth.TypPerson:
		person, err := aauth.VerifyAndExtractPerson(r.Context(), r, rs.url, rs.verify)
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		if person.Issuer != rs.sb.cfg.URL(RolePS) {
			aauth.WriteProblem(w, http.StatusForbidden, aauth.ErrCodeInvalidRequest, "person server not accepted")
			return
		}
	case aauth.TypAuth:
		claims, err := aauth.VerifyAndExtractAuth(r.Context(), r, rs.url, aauth.AuthTokenVerifyOptions{
			TokenVerifyOptions: rs.verify,
			CheckSubject: func(_ context.Context, iss, _ string) error {
				if iss != rs.audience {
					return fmt.Errorf("%w: unexpected issuer %s", aauth.ErrInvalidToken, iss)
				}
				return nil
			},
		})
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return
		}
		if claims.Scope == "" {
			aauth.WriteProblem(w, http.StatusForbidden, aauth.ErrCodeInvalidScope, "the auth token grants no scope")
			return
		}
	default:
		aauth.ChallengePersonToken(w)
		return
	}
	writeJSON(w, http.StatusOK, documentsBody)
}

// serveData is resource-managed access: a session token, or an
// interaction with the person.
func (rs *resource) serveData(w http.ResponseWriter, r *http.Request) {
	agent, err := aauth.VerifyAndExtractAgent(r.Context(), r, aauth.VerifyAgentTokenOptions{Resolver: rs.verify.Resolver})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	jkt := agent.Cnf.JWK.Thumbprint()
	if session := sessionToken(r); session != "" {
		rs.mu.Lock()
		owner, ok := rs.sessions[session]
		rs.mu.Unlock()
		if !ok || owner != jkt {
			aauth.WriteProblem(w, http.StatusUnauthorized, aauth.ErrCodeInvalidRequest, "unknown session")
			return
		}
		writeJSON(w, http.StatusOK, dataBody)
		return
	}
	if !aauth.CanRaise(r, aauth.RequirementInteraction) {
		aauth.WriteProblem(w, http.StatusForbidden, aauth.TokenErrUserUnreachable, "declare the interaction capability (AAuth-Capabilities: interaction) so the person can approve")
		return
	}
	code, err := interactioncode.Generate()
	if err != nil {
		aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
		return
	}
	id, err := randomID()
	if err != nil {
		aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, "")
		return
	}
	rs.mu.Lock()
	rs.pending[id] = &interaction{code: code, agentJKT: jkt}
	rs.mu.Unlock()
	if rs.sb.cfg.Consent == ConsentAuto {
		if err := rs.approve(code); err != nil {
			aauth.WriteProblem(w, http.StatusInternalServerError, aauth.ErrCodeServerError, err.Error())
			return
		}
	}
	aauth.ChainInteraction(w, rs.url+PathPending+id, rs.url+PathInteraction, code)
}

// sessionToken reads a session token presented as Authorization: AAuth
// (draft-11 §6.3) or, as aauth-go's walkthrough sends it, AAuth-Access.
func sessionToken(r *http.Request) string {
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "AAuth "); ok {
		return strings.TrimSpace(v)
	}
	return r.Header.Get(aauth.HeaderAAuthAccess)
}

// servePending answers a poll: still pending, or the data with the
// session token in AAuth-Access.
func (rs *resource) servePending(w http.ResponseWriter, r *http.Request) {
	agent, err := aauth.VerifyAndExtractAgent(r.Context(), r, aauth.VerifyAgentTokenOptions{Resolver: rs.verify.Resolver})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	rs.mu.Lock()
	p := rs.pending[strings.TrimPrefix(r.URL.Path, PathPending)]
	var session string
	if p != nil {
		session = p.session
	}
	rs.mu.Unlock()
	if p == nil || p.agentJKT != agent.Cnf.JWK.Thumbprint() {
		aauth.WriteProblem(w, http.StatusNotFound, aauth.ErrCodeInvalidRequest, "no such request")
		return
	}
	if session == "" {
		w.Header().Set(aauth.HeaderLocation, rs.url+r.URL.Path)
		w.Header().Set(aauth.HeaderRetryAfter, "1")
		writeJSON(w, http.StatusAccepted, aauth.PendingStatus{Status: "pending"})
		return
	}
	w.Header().Set(aauth.HeaderAAuthAccess, session)
	writeJSON(w, http.StatusOK, dataBody)
}

// approve approves the interaction a code names, creating its session.
func (rs *resource) approve(code string) error {
	want, err := interactioncode.Canonicalize(code)
	if err != nil {
		return err
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, p := range rs.pending {
		c, err := interactioncode.Canonicalize(p.code)
		if err != nil || c != want || p.session != "" {
			continue
		}
		session, err := randomID()
		if err != nil {
			return err
		}
		p.session = session
		rs.sessions[session] = p.agentJKT
		return nil
	}
	return fmt.Errorf("unknown or used code")
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AAuth sandbox consent</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
button{font:inherit;padding:.5rem 1.25rem}code{background:#f2f4f7;padding:.1rem .3rem;border-radius:4px}</style></head>
<body><h1>{{.Title}}</h1><p>{{.Text}}</p>
{{if .Code}}<form method="post"><input type="hidden" name="code" value="{{.Code}}">
<p>Code <code>{{.Code}}</code>, approving as <strong>{{.Person}}</strong>.</p><button type="submit">Approve</button></form>{{end}}
<p><small>AAuth sandbox: a development tool.</small></p></body></html>`))

type pageData struct{ Title, Text, Code, Person string }

func renderPage(w http.ResponseWriter, status int, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	// The status line is sent; a template failure here can only be a
	// broken connection, which the client already sees.
	_ = consentPage.Execute(w, d) //nolint:errcheck // see above
}

// serveInteractionPage shows the approval page (GET) and approves (POST).
func (rs *resource) serveInteractionPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderPage(w, http.StatusOK, pageData{Title: "Approve agent access", Text: "An agent asks to read your data at " + rs.url + ".", Code: r.URL.Query().Get("code"), Person: rs.sb.cfg.Person})
	case http.MethodPost:
		if err := rs.approve(r.FormValue("code")); err != nil {
			renderPage(w, http.StatusBadRequest, pageData{Title: "Not approved", Text: err.Error()})
			return
		}
		renderPage(w, http.StatusOK, pageData{Title: "Approved", Text: "You can return to your agent."})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// serveApprove is the headless approval endpoint: POST ?code=.
func (rs *resource) serveApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := rs.approve(r.URL.Query().Get("code")); err != nil {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "person": rs.sb.cfg.Person})
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sandbox: random identifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
