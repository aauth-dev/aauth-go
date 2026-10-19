package aauth

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestFormatCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    string
		wantErr bool
	}{
		{"empty", nil, "", false},
		{"one", []string{CapabilityInteraction}, "interaction", false},
		{"draft example", []string{CapabilityInteraction, CapabilityClarification, CapabilityPayment}, "interaction, clarification, payment", false},
		{"duplicates and empties dropped", []string{"payment", "", "payment", "interaction"}, "payment, interaction", false},
		{"extension token", []string{"x-vendor"}, "x-vendor", false},
		{"not a token", []string{"has space"}, "", true},
		{"leading digit", []string{"1st"}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FormatCapabilities(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{"absent", nil, nil, false},
		{"blank", []string{" "}, nil, false},
		{"draft example", []string{"interaction, clarification, payment"}, []string{"interaction", "clarification", "payment"}, false},
		{"parameters ignored", []string{"interaction;v=2, payment"}, []string{"interaction", "payment"}, false},
		{"unknown kept for caller", []string{"teleport"}, []string{"teleport"}, false},
		{"split field lines", []string{"interaction", "payment"}, []string{"interaction", "payment"}, false},
		{"non-token members skipped", []string{`interaction, "quoted", 7`}, []string{"interaction"}, false},
		{"duplicates collapsed", []string{"payment, payment"}, []string{"payment"}, false},
		{"malformed", []string{"interaction,,"}, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCapabilities(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCanRaise(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		requirement string
		want        bool
	}{
		{"interaction declared", "interaction", RequirementInteraction, true},
		{"interaction absent", "", RequirementInteraction, false},
		{"interaction not declared", "payment", RequirementInteraction, false},
		{"clarification declared", "clarification", RequirementClarification, true},
		{"clarification absent", "", RequirementClarification, false},
		{"malformed header declares nothing", "interaction,,", RequirementInteraction, false},
		{"auth-token needs no capability", "", RequirementAuthToken, true},
		{"approval needs no capability", "", RequirementApproval, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://files.example/x", nil)
			if tc.header != "" {
				r.Header.Set(HeaderCapabilities, tc.header)
			}
			if got := CanRaise(r, tc.requirement); got != tc.want {
				t.Fatalf("CanRaise = %v, want %v", got, tc.want)
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, "https://files.example/x", nil)
	r.Header.Set(HeaderCapabilities, "payment")
	if !CanRequirePayment(r) {
		t.Fatal("CanRequirePayment = false with payment declared")
	}
}

func TestTransportDeclaresCapabilities(t *testing.T) {
	agent := testAgent(t)
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if _, err := VerifyAndExtractAgent(req.Context(), req, VerifyAgentTokenOptions{Resolver: SelfSignedResolver{}}); err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)
			return
		}
		seen = append(seen, req.Header.Get(HeaderCapabilities))
		writeBody(t, rw, "ok")
	}))
	defer srv.Close()

	tests := []struct {
		name    string
		own     []string
		mission []string
		want    string
	}{
		{"none", nil, nil, ""},
		{"own", []string{CapabilityInteraction}, nil, "interaction"},
		{"union with mission", []string{CapabilityInteraction}, []string{CapabilityPayment, CapabilityInteraction}, "interaction, payment"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seen = nil
			tr := NewTransport(agent, nil)
			tr.Capabilities, tr.MissionCapabilities = tc.own, tc.mission
			req, err := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(HeaderCapabilities, "stale") // replaced, never forwarded
			res, err := (&http.Client{Transport: tr}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			closeBody(res.Body)
			if len(seen) != 1 || seen[0] != tc.want {
				t.Fatalf("resource saw %q, want %q", seen, tc.want)
			}
		})
	}

	tr := NewTransport(agent, nil)
	tr.Capabilities = []string{"not a token"}
	if _, err := (&http.Client{Transport: tr}).Get(srv.URL + "/x"); err == nil {
		t.Fatal("invalid capability value: want error")
	}
}
