package aauth

import (
	"net/http/httptest"
	"testing"
)

func TestInteractionResponsesAreJSON(t *testing.T) {
	for name, write := range map[string]func(*httptest.ResponseRecorder){
		"interaction": func(w *httptest.ResponseRecorder) {
			ChainInteraction(w, "/pending/1", "https://ps.example/interaction", "ABCD-EFGH")
		},
		"clarification": func(w *httptest.ResponseRecorder) { WriteClarification(w, "/pending/1", "Which folder?", 0, nil) },
	} {
		w := httptest.NewRecorder()
		write(w)
		if got := w.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("%s: Content-Type %q", name, got)
		}
	}
}
