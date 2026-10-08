package accessserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aauth-dev/auth-go/personserver"
)

// PS-AS collapse (draft -11 §9.3.3): when the agent's PS and the
// resource's AS are the same server, federation collapses to a single
// internal evaluation. [Server.Local] returns a [personserver.Federator]
// that runs the AS's token endpoint logic in-process for one PS — no
// signed hop, trust implicit — while the resource still sees an auth
// token from the AS (dwk aauth-access.json) carrying the AS's policy
// verdict. Pending requests, claims, and clarification work as over HTTP.
//
//	as, _ := accessserver.New(asConfig)
//	ps, _ := personserver.New(personserver.Config{..., Federator: as.Local(psIssuer)})

// Local returns an in-process Federator for the PS ps, which must be the
// PS sharing this server (its issuer).
func (s *Server) Local(ps string) personserver.Federator { return &local{s: s, ps: ps} }

type local struct {
	s  *Server
	ps string
}

func (l *local) Federate(ctx context.Context, r *personserver.FederationRequest) (*personserver.FederationResponse, error) {
	if r.AccessServer != l.s.cfg.Issuer {
		return nil, errors.New("accessserver: the in-process federator only serves its own access server")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	res, p, err := l.s.handle(ctx, l.ps, body, l.s.now())
	if err != nil {
		return nil, err
	}
	return l.convert(res, p)
}

func (l *local) Poll(ctx context.Context, pendingURL string) (*personserver.FederationResponse, error) {
	p, err := l.pending(ctx, pendingURL)
	if err != nil {
		return nil, err
	}
	p = l.s.step(ctx, p)
	return l.convert(p.Result, p)
}

func (l *local) Answer(ctx context.Context, pendingURL string, body any) error {
	p, err := l.pending(ctx, pendingURL)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = l.s.answer(ctx, p, raw, l.s.now())
	return err
}

func (l *local) pending(ctx context.Context, pendingURL string) (*Pending, error) {
	id, ok := strings.CutPrefix(pendingURL, l.s.url(l.s.paths.Pending))
	if !ok {
		return nil, errors.New("accessserver: not this access server's pending URL")
	}
	p, err := l.s.cfg.Store.Pending(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.PS != l.ps {
		return nil, ErrNotFound
	}
	return p, nil
}

// convert renders an outcome exactly as the HTTP endpoint would, and
// parses it as the HTTP client would.
func (l *local) convert(res *Result, p *Pending) (*personserver.FederationResponse, error) {
	rec := &recorder{h: http.Header{}}
	if res != nil {
		res.write(rec)
	} else {
		l.s.writePending(rec, p)
	}
	u, err := url.Parse(l.s.url(l.s.paths.Token))
	if err != nil {
		return nil, err
	}
	return parseResponse(u, &http.Response{StatusCode: rec.status, Header: rec.h, Body: io.NopCloser(&rec.buf)})
}

// recorder captures a response written in-process.
type recorder struct {
	h      http.Header
	status int
	buf    bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.h }
func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.buf.Write(b)
}
