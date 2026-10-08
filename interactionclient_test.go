package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// interactionPS serves the interaction endpoint (§7.6).
func interactionPS(t *testing.T, handle func(http.ResponseWriter, InteractionRequest)) *PSClient {
	t.Helper()
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /interaction", func(rw http.ResponseWriter, r *http.Request) {
		if _, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}, Signature: RequestVerifyOptions{RequireBodyCoverage: true}}); err != nil {
			WriteSignatureFailure(rw, err)
			return
		}
		var ir InteractionRequest
		if err := json.NewDecoder(r.Body).Decode(&ir); err != nil {
			WriteProblem(rw, http.StatusBadRequest, ErrCodeInvalidRequest, err.Error())
			return
		}
		handle(rw, ir)
	})
	mux.HandleFunc("GET /pending/i1", func(rw http.ResponseWriter, _ *http.Request) {
		if polls.Add(1) == 1 {
			rw.Header().Set(HeaderLocation, "/pending/i1")
			rw.Header().Set(HeaderRetryAfter, "0")
			rw.WriteHeader(http.StatusAccepted)
			writeBody(t, rw, `{"status":"interacting"}`)
			return
		}
		rw.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return NewPSClient(srv.URL, testAgent(t))
}

func TestRequestInteractionQuestion(t *testing.T) {
	var got InteractionRequest
	c := interactionPS(t, func(rw http.ResponseWriter, ir InteractionRequest) {
		got = ir
		writeJSON(t, rw, InteractionResponse{Answer: "Yes, go ahead with the refundable option."})
	})
	res, err := c.RequestInteraction(context.Background(), InteractionRequest{
		Type: InteractionTypeQuestion, Question: "Refundable or not?", MissionS256: "m-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Answer != "Yes, go ahead with the refundable option." || got.Question != "Refundable or not?" || got.MissionS256 != "m-1" {
		t.Fatalf("answer %+v, PS saw %+v", res, got)
	}
}

func TestRelayInteraction(t *testing.T) {
	// §11.6.3.2: the agent relays a resource's interaction through the PS,
	// which defers while it reaches the user.
	var got InteractionRequest
	c := interactionPS(t, func(rw http.ResponseWriter, ir InteractionRequest) {
		got = ir
		rw.Header().Set(HeaderLocation, "/pending/i1")
		rw.Header().Set(HeaderRetryAfter, "0")
		rw.WriteHeader(http.StatusAccepted)
		writeBody(t, rw, `{"status":"pending"}`)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := Requirement{Requirement: RequirementInteraction, URL: "https://booking.example/confirm", Code: "X7K2-M9P4"}
	if _, err := c.RelayInteraction(ctx, r, "Confirm the booking", ""); err != nil {
		t.Fatal(err)
	}
	if got.Type != InteractionTypeInteraction || got.URL != r.URL || got.Code != r.Code || got.Description != "Confirm the booking" {
		t.Fatalf("PS saw %+v", got)
	}
	if _, err := c.RelayInteraction(ctx, Requirement{Requirement: RequirementApproval}, "", ""); err == nil {
		t.Fatal("relayed a non-interaction requirement")
	}
}

func TestRequestInteractionErrors(t *testing.T) {
	var reply func(http.ResponseWriter)
	c := interactionPS(t, func(rw http.ResponseWriter, _ InteractionRequest) { reply(rw) })
	ctx := context.Background()
	relay := InteractionRequest{Type: InteractionTypePayment, URL: "https://pay.example/approve", Code: "ABCD-EFGH"}

	reply = func(rw http.ResponseWriter) {
		WriteProblem(rw, http.StatusFailedDependency, ErrCodeInteractionUnavailable, "no channel")
	}
	_, err := c.RequestInteraction(ctx, relay)
	var pe *ProblemError
	if !errors.Is(err, ErrInteractionUnavailable) || !errors.As(err, &pe) || pe.Status != http.StatusFailedDependency {
		t.Errorf("interaction_unavailable: err = %v", err)
	}

	reply = func(rw http.ResponseWriter) {
		WriteProblem(rw, http.StatusForbidden, TokenErrUserUnreachable, "")
	}
	_, err = c.RequestInteraction(ctx, relay)
	if !errors.As(err, &pe) || pe.Code != TokenErrUserUnreachable || errors.Is(err, ErrInteractionUnavailable) {
		t.Errorf("user_unreachable: err = %v", err)
	}

	reply = func(rw http.ResponseWriter) { WriteMissionTerminated(rw, TerminationRevoked) }
	_, err = c.RequestInteraction(ctx, relay)
	var mse *MissionStatusError
	if !errors.As(err, &mse) || mse.TerminationReason != TerminationRevoked {
		t.Errorf("mission terminated: err = %v", err)
	}

	for _, bad := range []InteractionRequest{
		{Type: "completion"},
		{Type: InteractionTypeQuestion},
		{Type: InteractionTypeInteraction},
	} {
		if _, err := c.RequestInteraction(ctx, bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
