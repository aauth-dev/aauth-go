package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestMetadataValidate(t *testing.T) {
	sm := ServerMetadata{Issuer: "https://ps.example", JWKSURI: "https://ps.example/jwks.json"}
	ps := PersonServerMetadata{ServerMetadata: sm, AuthTokenEndpoint: "https://ps.example/token", PersonTokenEndpoint: "https://ps.example/person"}
	if err := ps.Validate(); err != nil {
		t.Fatal(err)
	}
	noPerson := ps
	noPerson.PersonTokenEndpoint = ""
	as := AccessServerMetadata{ServerMetadata: sm}
	for name, err := range map[string]error{
		"ps without person_token_endpoint": noPerson.Validate(),
		"as without auth_token_endpoint":   as.Validate(),
		"agent provider without jwks_uri":  AgentProviderMetadata{ServerMetadata: ServerMetadata{Issuer: "https://a.example"}}.Validate(),
		"resource without issuer":          ResourceMetadata{}.Validate(),
	} {
		if !errors.Is(err, ErrMetadataIncomplete) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A resource that only verifies agent signatures publishes no keys.
	if err := (ResourceMetadata{ServerMetadata: ServerMetadata{Issuer: "https://r.example"}}).Validate(); err != nil {
		t.Errorf("resource without jwks_uri: %v", err)
	}
}

func TestResourceLinks(t *testing.T) {
	h := http.Header{}
	h.Add("Link", ResourceMetadataLink("https://api.example"))
	h.Add("Link", `<https://docs.example/style.css>; rel=stylesheet, <https://two.example/.well-known/aauth-resource.json>; title="a, b"; rel="preload AAuth-Resource"`)
	h.Add("Link", `<https://api.example/.well-known/aauth-resource.json>; rel="aauth-resource"`) // duplicate
	h.Add("Link", `<http://insecure.example/.well-known/aauth-resource.json>; rel="aauth-resource"`)
	h.Add("Link", `<https://api.example/v1/.well-known/aauth-resource.json>; rel="aauth-resource"`)
	h.Add("Link", `<https://api.example/.well-known/aauth-person.json>; rel="aauth-resource"`)
	h.Add("Link", `</.well-known/aauth-resource.json>; rel="aauth-resource"`)
	h.Add("Link", `<https://three.example/.well-known/aauth-resource.json>; rel="other"; rel="aauth-resource"`) // only the first rel counts
	got := ResourceLinks(h)
	want := []string{"https://api.example", "https://two.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResourceLinks = %q, want %q", got, want)
	}
	if got := ResourceLinks(http.Header{"Link": {"garbage", `<unterminated`}}); len(got) != 0 {
		t.Fatalf("malformed: %q", got)
	}
}

func TestPSClientDiscover(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/"+WellKnownPerson {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, PersonServerMetadata{
			ServerMetadata:      ServerMetadata{Issuer: base, JWKSURI: base + "/jwks.json"},
			AuthTokenEndpoint:   base + "/oauth/token",
			PersonTokenEndpoint: base + "/oauth/person",
			MissionEndpoint:     base + "/missions",
		})
	}))
	defer srv.Close()
	base = srv.URL
	c := NewPSClient(base, testAgent(t))
	c.PermissionEndpoint = "https://override.example/permission"
	md, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if md.Issuer != base || c.Issuer() != base || c.Metadata() != md {
		t.Fatalf("metadata %+v", md)
	}
	if c.AuthTokenEndpoint != base+"/oauth/token" || c.PersonTokenEndpoint != base+"/oauth/person" ||
		c.MissionEndpoint != base+"/missions" || c.PermissionEndpoint != "https://override.example/permission" {
		t.Fatalf("endpoints %+v", c)
	}
	// Unpublished optional endpoints fall back to BaseURL paths.
	if got := c.endpoint(c.AuditEndpoint, "/audit"); got != base+"/audit" {
		t.Fatalf("audit endpoint %q", got)
	}
}

func TestPSClientDiscoverRejectsIncomplete(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]string{"issuer": base, "jwks_uri": base + "/jwks.json", "token_endpoint": base + "/token"})
	}))
	defer srv.Close()
	base = srv.URL
	if _, err := NewPSClient(base, testAgent(t)).Discover(context.Background()); !errors.Is(err, ErrMetadataIncomplete) {
		t.Fatalf("err = %v, want ErrMetadataIncomplete (a draft -09 token_endpoint is not auth_token_endpoint)", err)
	}
}

// writeJSON writes v as a 200 application/json response.
func writeJSON(t testing.TB, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error(err)
	}
}
