package aauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestClarificationChat drives the full §7.3 dialog: the agent asks for
// permission, the PS defers with a clarification question, the agent answers,
// and the PS then grants.
func TestClarificationChat(t *testing.T) {
	agent := testAgent(t)
	var answered atomic.Bool
	var gotAnswer string

	mux := http.NewServeMux()
	mux.HandleFunc("POST /permission", func(w http.ResponseWriter, r *http.Request) {
		if _, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		WriteClarification(w, "/pending/c1", "Why do you need calendar write access?", 120, nil)
	})
	mux.HandleFunc("/pending/c1", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			p, err := ParseClarificationPost(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			gotAnswer = p.ClarificationResponse
			answered.Store(true)
			w.WriteHeader(http.StatusOK) // ack; state advances on next poll
		case http.MethodGet:
			if answered.Load() {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(PermissionResponse{Permission: PermissionGranted})
				return
			}
			// Still waiting for the answer — repeat the clarification.
			WriteClarification(w, "/pending/c1", "Why do you need calendar write access?", 120, nil)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewPSClient(srv.URL, agent)
	c.OnClarification = func(q Clarification) (ClarificationReply, error) {
		if q.Question == "" || q.Timeout != 120 {
			t.Errorf("unexpected clarification %+v", q)
		}
		return ClarificationReply{Text: "To create a meeting invite for the people you listed."}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := c.RequestPermission(ctx, PermissionRequest{Action: "WriteCalendar"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Granted() {
		t.Fatalf("want granted after clarification, got %+v", res)
	}
	if gotAnswer != "To create a meeting invite for the people you listed." {
		t.Fatalf("PS received answer %q", gotAnswer)
	}
}

// TestClarificationCancel: the agent withdraws the request via DELETE.
func TestClarificationCancel(t *testing.T) {
	agent := testAgent(t)
	var deleted atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("POST /permission", func(w http.ResponseWriter, r *http.Request) {
		if _, err := VerifyAndExtractAgent(r.Context(), r, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		WriteClarification(w, "/pending/c2", "Explain yourself", 60, []string{"a", "b"})
	})
	mux.HandleFunc("DELETE /pending/c2", func(w http.ResponseWriter, r *http.Request) {
		deleted.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewPSClient(srv.URL, agent)
	c.OnClarification = func(q Clarification) (ClarificationReply, error) {
		if len(q.Options) != 2 {
			t.Errorf("options = %v", q.Options)
		}
		return ClarificationReply{Cancel: true}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Cancellation ends in a non-granted terminal response.
	// A DELETE→200 body isn't a PermissionResponse; RequestPermission may
	// surface it as a decode/parse error or as a non-granted response.
	// Either outcome is acceptable here: what matters is that the DELETE
	// happened, which is asserted below.
	if res, err := c.RequestPermission(ctx, PermissionRequest{Action: "X"}); err == nil && res.Granted() {
		t.Fatal("cancelled request reported as granted")
	}
	if !deleted.Load() {
		t.Fatal("cancel did not DELETE the pending URL")
	}
}

func TestParseClarificationPostRejectsUnknownAction(t *testing.T) {
	body := `{"action":"nonsense"}`
	req := httptest.NewRequest(http.MethodPost, "/pending/x", strings.NewReader(body))
	if _, err := ParseClarificationPost(req); err != ErrUnknownAction {
		t.Fatalf("err = %v, want ErrUnknownAction", err)
	}
}
