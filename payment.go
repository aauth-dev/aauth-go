package aauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxSettlements bounds the 402 responses one request settles, so a server
// that keeps asking for payment cannot hold a request forever.
const maxSettlements = 3

// PaymentRequiredError is a 402 Payment Required response (draft -11 §6.5,
// §9.1.2, §11.6, §11.8.4). AAuth carries only the shape: the payment itself
// is described by a payment protocol such as x402 or the HTTP Payment
// authentication scheme, which this package passes through unparsed. The
// payer settles it (see [PaymentHandler]) and then polls Location, or
// retries the request when there is no Location.
type PaymentRequiredError struct {
	// Server is the origin that answered 402 (scheme://host), so a payer
	// can keep one billing relationship per server.
	Server string
	// Location is the absolute URL to poll once payment is settled. An
	// access server MUST send it (§9.1.2); a resource may not.
	Location string
	// Requirement is the AAuth-Requirement sent with the 402, if any: a
	// 402 with requirement=auth-token says authorization and payment are
	// both required (§6.5, §11.6).
	Requirement *Requirement
	// Challenges are the response's WWW-Authenticate values, which carry
	// payment challenges such as the Payment scheme. AAuth never conveys
	// its own requirements there (§11.6).
	Challenges []string
	// ContentType and Body are the response body, such as x402 payment
	// requirements, unparsed.
	ContentType string
	Body        []byte
}

// Error implements error.
func (e *PaymentRequiredError) Error() string {
	if e.Location != "" {
		return fmt.Sprintf("aauth: %s requires payment (settle, then poll %s)", e.Server, e.Location)
	}
	return fmt.Sprintf("aauth: %s requires payment", e.Server)
}

// PaymentChallenges returns the WWW-Authenticate challenges that use the
// Payment authentication scheme, unparsed.
func (e *PaymentRequiredError) PaymentChallenges() []string {
	var out []string
	for _, c := range e.Challenges {
		scheme, _, _ := strings.Cut(strings.TrimSpace(c), " ")
		if strings.EqualFold(scheme, "Payment") {
			out = append(out, c)
		}
	}
	return out
}

// NewPaymentRequiredError builds the error for a 402 response to a request
// sent to reqURL, with the response's header and body. Location is resolved
// against reqURL and must be same-origin; an AAuth-Requirement that does
// not parse is an error.
func NewPaymentRequiredError(reqURL *url.URL, h http.Header, body []byte) (*PaymentRequiredError, error) {
	e := &PaymentRequiredError{
		Server:      reqURL.Scheme + "://" + reqURL.Host,
		Challenges:  h.Values("WWW-Authenticate"),
		ContentType: h.Get("Content-Type"),
		Body:        body,
	}
	if loc := h.Get(HeaderLocation); loc != "" {
		u, err := reqURL.Parse(loc)
		if err != nil {
			return nil, fmt.Errorf("aauth: 402 Location: %w", err)
		}
		if u.Scheme != reqURL.Scheme || u.Host != reqURL.Host {
			return nil, fmt.Errorf("aauth: 402 Location %q is not same-origin", u)
		}
		e.Location = u.String()
	}
	if rh := h.Get(HeaderRequirement); rh != "" {
		r, err := ParseRequirement(rh)
		if err != nil {
			return nil, err
		}
		e.Requirement = &r
	}
	return e, nil
}

// PaymentRequiredFromResponse reads and closes the body of a 402 response
// to a request sent to reqURL and returns its [PaymentRequiredError].
func PaymentRequiredFromResponse(reqURL *url.URL, res *http.Response) (*PaymentRequiredError, error) {
	defer closeBody(res.Body)
	body, err := io.ReadAll(io.LimitReader(res.Body, maxDocumentBytes))
	if err != nil {
		return nil, fmt.Errorf("aauth: 402 body: %w", err)
	}
	return NewPaymentRequiredError(reqURL, res.Header, body)
}

// PaymentHandler settles a payment a server asked for with 402 (draft -11
// §11.8.4: settle payment, poll Location). Settle returns once payment is
// settled, or an error to stop. Payment protocols, settlement and billing
// terms are outside AAuth; a handler that pays the same server repeatedly
// can keep its billing relationship keyed by [PaymentRequiredError.Server],
// as a PS does per access server (§9.1.2).
type PaymentHandler interface {
	Settle(ctx context.Context, p *PaymentRequiredError) error
}

// PaymentHandlerFunc adapts a function to [PaymentHandler].
type PaymentHandlerFunc func(ctx context.Context, p *PaymentRequiredError) error

// Settle implements [PaymentHandler].
func (f PaymentHandlerFunc) Settle(ctx context.Context, p *PaymentRequiredError) error {
	return f(ctx, p)
}
