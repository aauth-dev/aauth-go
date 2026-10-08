package aauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Deferred responses (draft -11 §11.8): any AAuth endpoint MAY answer
// 202 Accepted with a Location pending URL when it cannot resolve a request
// immediately — the protocol's first-class "wait for the human" primitive.
// The agent then polls the pending URL with signed GETs, honoring
// Retry-After, backing off linearly on 429 (per RFC 8628 §3.5's pattern),
// until a non-202 terminal response arrives.

// PendingStatus is the body of a 202 pending response.
type PendingStatus struct {
	// Status is "pending", or "interacting" once the user has arrived at an
	// interaction endpoint. Unrecognized values MUST be treated as pending.
	Status string `json:"status"`
	// Clarification, when present with requirement=clarification (§7.3.1),
	// is a Markdown question the recipient must answer before proceeding.
	Clarification string `json:"clarification,omitempty"`
	// Timeout is the optional deadline (seconds) to answer a clarification.
	Timeout int `json:"timeout,omitempty"`
	// Options are discrete answer choices, when the question has them.
	Options []string `json:"options,omitempty"`
}

// Clarification is a question posed during a deferred flow (§7.3.1) that the
// agent must answer before the request can proceed.
type Clarification struct {
	Question string   // the Markdown question to answer
	Timeout  int      // seconds until the server times out the request (0 if unset)
	Options  []string // discrete answer choices, when the question has them
}

// Clarification response actions (draft -11 §7.5.2).
const (
	ActionClarificationResponse = "clarification_response"
	ActionUpdatedRequest        = "updated_request"
)

// ClarificationReply is the agent's answer to a Clarification (draft -11
// §7.5.2):
//
//   - Text set → clarification_response (answer the question).
//   - ResourceToken set → updated_request (replace the request). The
//     PresentedToken the agent used at the resource to obtain the new
//     resource token is REQUIRED with it; the PS verifies the pair as for
//     an auth token request. The new resource token MUST share iss, ps,
//     sub, agent_jkt, mission_s256, and tenant with the original, and its
//     presented_jti MUST be PresentedToken's jti (§7.5.2.2).
//   - Cancel true → DELETE the pending URL, withdrawing the request.
type ClarificationReply struct {
	Text           string // the answer, for a clarification_response
	ResourceToken  string // a replacement resource token, for an updated_request
	PresentedToken string // the token presented to obtain ResourceToken (REQUIRED with it)
	Justification  string // optional (RECOMMENDED) reason accompanying an updated_request
	Cancel         bool   // withdraw the request (DELETE the pending URL)
}

// DeferredOptions tunes DoDeferred.
type DeferredOptions struct {
	// PreferWaitSeconds is sent as `Prefer: wait=N` on polling GETs to
	// request long-poll behavior. 0 omits the header.
	PreferWaitSeconds int
	// DefaultPollInterval applies when a 202 carries no Retry-After
	// (spec default: 5s).
	DefaultPollInterval time.Duration
	// MaxPolls bounds the polling loop as a safety valve. 0 = unbounded
	// (the context deadline is then the only limit).
	MaxPolls int
	// Sign re-signs each polling GET. Deferred polling of a signed endpoint
	// keeps presenting the agent's identity; leave nil for unsigned polls.
	Sign func(*http.Request) error
	// OnRequirement is invoked once per distinct AAuth-Requirement header
	// seen on a 202 (e.g. requirement=interaction; url=…; code=…) so the
	// caller can surface the interaction to the user while polling continues.
	OnRequirement func(Requirement)
	// HandleRequirement, when set, is invoked like OnRequirement (once per
	// distinct AAuth-Requirement on a 202, before the next poll) for a
	// requirement the caller satisfies itself — for example an auth-token
	// requirement delivered as a deferred response (draft -11 §6.5.1),
	// after which Sign presents the auth token on the polls. An error
	// stops polling and is returned.
	HandleRequirement func(Requirement) error
	// OnClarification answers a requirement=clarification 202 (§7.3): given
	// the question, it returns the agent's reply. If nil, a clarification
	// requirement is treated as an ordinary pending state (polling continues
	// without answering — which will eventually time out server-side).
	OnClarification func(Clarification) (ClarificationReply, error)
}

// DoDeferred executes req and follows the §11.8.4 state machine until a
// terminal (non-202) response. The caller owns closing the returned body.
func DoDeferred(ctx context.Context, hc *http.Client, req *http.Request, opts DeferredOptions) (*http.Response, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	return FollowDeferred(ctx, hc, req.URL, res, opts)
}

// FollowDeferred continues the §11.8.4 state machine from an already-received
// response: if res is not a 202 it is returned unchanged; otherwise the
// pending URL is polled until a terminal response arrives. reqURL is the URL
// the original request was sent to (for same-origin Location resolution).
func FollowDeferred(ctx context.Context, hc *http.Client, reqURL *url.URL, res *http.Response, opts DeferredOptions) (*http.Response, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if opts.DefaultPollInterval <= 0 {
		opts.DefaultPollInterval = 5 * time.Second
	}
	backoff := time.Duration(0)
	polls := 0
	lastReq := ""

	for res.StatusCode == http.StatusAccepted {
		if rh := res.Header.Get(HeaderRequirement); rh != "" && rh != lastReq {
			lastReq = rh
			// A requirement this agent cannot parse is not surfaced; the
			// 202 is still followed as an ordinary pending state.
			if parsed, perr := ParseRequirement(rh); perr == nil {
				if opts.OnRequirement != nil {
					opts.OnRequirement(parsed)
				}
				if opts.HandleRequirement != nil {
					if err := opts.HandleRequirement(parsed); err != nil {
						drainBody(res.Body)
						return nil, err
					}
				}
			}
		}
		pendingURL, retryAfter, status, err := readPending(reqURL, res)
		if err != nil {
			return nil, err
		}
		if opts.MaxPolls > 0 && polls >= opts.MaxPolls {
			return nil, fmt.Errorf("aauth: deferred response still pending after %d polls", polls)
		}

		// requirement=clarification (§7.3): answer, then resume polling.
		if status.Clarification != "" && opts.OnClarification != nil {
			done, err := answerClarification(ctx, hc, pendingURL, status, opts)
			if err != nil {
				return nil, err
			}
			if done != nil {
				return done, nil // cancelled → terminal response
			}
			polls++
			// After posting the answer, poll immediately for the next state.
			res, err = pollPending(ctx, hc, pendingURL, opts)
			if err != nil {
				return nil, err
			}
			continue
		}
		wait := retryAfter
		if wait < 0 {
			wait = opts.DefaultPollInterval
		}
		wait += backoff
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}

		res, err = pollPending(ctx, hc, pendingURL, opts)
		if err != nil {
			return nil, err
		}
		if res.StatusCode == http.StatusTooManyRequests {
			// Linear backoff: increase interval by 5s (§11.8.3).
			backoff += 5 * time.Second
			closeBody(res.Body)
			res = &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{}, Body: http.NoBody}
			// Reuse the same pending URL on the next iteration.
			res.Header.Set(HeaderLocation, pendingURL.String())
			res.Header.Set(HeaderRetryAfter, "0")
		}
	}
	return res, nil
}

// pollPending issues one signed GET against the pending URL.
func pollPending(ctx context.Context, hc *http.Client, pendingURL *url.URL, opts DeferredOptions) (*http.Response, error) {
	poll, err := http.NewRequestWithContext(ctx, http.MethodGet, pendingURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if opts.PreferWaitSeconds > 0 {
		poll.Header.Set(HeaderPrefer, fmt.Sprintf("wait=%d", opts.PreferWaitSeconds))
	}
	if opts.Sign != nil {
		if err := opts.Sign(poll); err != nil {
			return nil, fmt.Errorf("aauth: sign poll: %w", err)
		}
	}
	return hc.Do(poll)
}

// answerClarification posts the agent's reply to a clarification (§7.3.2).
// Returns a non-nil terminal response only when the reply cancels the request
// (DELETE) and the server answers with a final status; otherwise nil, and the
// caller resumes polling.
func answerClarification(ctx context.Context, hc *http.Client, pendingURL *url.URL, status PendingStatus, opts DeferredOptions) (*http.Response, error) {
	reply, err := opts.OnClarification(Clarification{
		Question: status.Clarification,
		Timeout:  status.Timeout,
		Options:  status.Options,
	})
	if err != nil {
		return nil, fmt.Errorf("aauth: clarification handler: %w", err)
	}

	if reply.Cancel {
		del, err := http.NewRequestWithContext(ctx, http.MethodDelete, pendingURL.String(), nil)
		if err != nil {
			return nil, err
		}
		if opts.Sign != nil {
			if err := opts.Sign(del); err != nil {
				return nil, fmt.Errorf("aauth: sign cancel: %w", err)
			}
		}
		res, err := hc.Do(del)
		if err != nil {
			return nil, err
		}
		return res, nil
	}

	var payload ClarificationPost
	switch {
	case reply.ResourceToken != "":
		if reply.PresentedToken == "" {
			return nil, fmt.Errorf("aauth: updated_request: %w", ErrPresentedTokenMissing)
		}
		payload = ClarificationPost{
			Action: ActionUpdatedRequest, ResourceToken: reply.ResourceToken,
			PresentedToken: reply.PresentedToken, Justification: reply.Justification,
		}
	default:
		payload = ClarificationPost{Action: ActionClarificationResponse, ClarificationResponse: reply.Text}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, pendingURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	post.Header.Set("Content-Type", "application/json")
	post.ContentLength = int64(len(body))
	post.Body = io.NopCloser(bytes.NewReader(body))
	if opts.Sign != nil {
		if err := opts.Sign(post); err != nil {
			return nil, fmt.Errorf("aauth: sign clarification: %w", err)
		}
	}
	res, err := hc.Do(post)
	if err != nil {
		return nil, err
	}
	closeBody(res.Body) // the answer is acknowledged; state advances via polling
	return nil, nil
}

// readPending validates a 202 response and extracts the same-origin pending
// URL, Retry-After (−1 when absent), and the parsed pending body.
func readPending(reqURL *url.URL, res *http.Response) (*url.URL, time.Duration, PendingStatus, error) {
	defer closeBody(res.Body)
	var ps PendingStatus
	loc := res.Header.Get(HeaderLocation)
	if loc == "" {
		return nil, 0, ps, fmt.Errorf("aauth: 202 without Location")
	}
	u, err := reqURL.Parse(loc)
	if err != nil {
		return nil, 0, ps, fmt.Errorf("aauth: 202 Location: %w", err)
	}
	// Location MUST be same-origin as the responding server (§11.8.2).
	if u.Scheme != reqURL.Scheme || u.Host != reqURL.Host {
		return nil, 0, ps, fmt.Errorf("aauth: 202 Location %q not same-origin as %q", u, reqURL)
	}
	retry := time.Duration(-1)
	if ra := res.Header.Get(HeaderRetryAfter); ra != "" {
		sec, err := strconv.Atoi(ra)
		if err != nil || sec < 0 {
			return nil, 0, ps, fmt.Errorf("aauth: bad Retry-After %q", ra)
		}
		retry = time.Duration(sec) * time.Second
	}
	// status field is informational; unrecognized statuses are pending
	// (§11.8.2). clarification/timeout/options drive the §7.5 flow.
	_ = json.NewDecoder(io.LimitReader(res.Body, 8192)).Decode(&ps)
	return u, retry, ps, nil
}
