package sandbox

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// page sends a browser request (no signing) and returns the status and
// body.
func (h *harness) page(method, target string, form url.Values) (int, http.Header, string) {
	h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		h.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, err := h.sb.Client("person").Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			h.t.Error(err)
		}
	}()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return res.StatusCode, res.Header, string(b)
}

// pendingAuthToken starts PS authorization at the resource role and
// returns the agent token, the Location to poll and the interaction code
// of the person server's 202.
func (h *harness) pendingAuthToken() (agent, location, code string) {
	h.t.Helper()
	agent = h.agentToken()
	resource := h.url(RoleResource, "")
	person := h.personToken(agent, resource)
	status, _, body := h.call(http.MethodPost, h.url(RoleResource, "/authorize"),
		map[string]string{HeaderPresent: PresentPerson, HeaderToken: person}, map[string]any{"scope": "data.read"})
	want(h.t, "authorize", status, http.StatusOK, body)
	rt, _ := body["resource_token"].(string)
	status, hdr, body := h.call(http.MethodPost, h.url(RolePS, PathToken),
		map[string]string{HeaderPresent: PresentAgent, HeaderToken: agent},
		map[string]any{"resource_token": rt, "presented_token": person, "capabilities": []string{"interaction"}})
	want(h.t, "auth token request", status, http.StatusAccepted, body)
	code = between(hdr.Get("AAuth-Requirement"), `code="`, `"`)
	if code == "" || hdr.Get("Location") == "" {
		h.t.Fatalf("202 without a code or Location: %v", hdr)
	}
	return agent, hdr.Get("Location"), code
}

func TestPersonServerConsentPage(t *testing.T) {
	h := newHarness(t, Config{Consent: ConsentManual, Person: "bob"})
	agent, loc, code := h.pendingAuthToken()
	poll := map[string]string{HeaderPresent: PresentAgent, HeaderToken: agent}

	status, _, page := h.page(http.MethodGet, h.url(RolePS, PathInteraction+"?code="+url.QueryEscape(code)), nil)
	if status != http.StatusOK || !strings.Contains(page, code) || !strings.Contains(page, "<strong>bob</strong>") || !strings.Contains(page, "<form") {
		t.Fatalf("consent page %d:\n%s", status, page)
	}
	status, _, body := h.call(http.MethodGet, loc, poll, nil)
	want(t, "poll before approval", status, http.StatusAccepted, body)

	status, _, page = h.page(http.MethodPost, h.url(RolePS, PathInteraction), url.Values{"code": {"ZZZZ-ZZZZ"}})
	if status != http.StatusBadRequest || !strings.Contains(page, "Not approved") {
		t.Fatalf("unknown code %d:\n%s", status, page)
	}
	status, _, page = h.page(http.MethodPost, h.url(RolePS, PathInteraction), url.Values{"code": {code}})
	if status != http.StatusOK || !strings.Contains(page, "Approved") {
		t.Fatalf("approve %d:\n%s", status, page)
	}
	status, _, body = h.call(http.MethodGet, loc, poll, nil)
	want(t, "poll after approval", status, http.StatusOK, body)
	if at, _ := body["auth_token"].(string); at == "" {
		t.Fatalf("no auth_token after approval: %v", body)
	}

	status, hdr, _ := h.page(http.MethodDelete, h.url(RolePS, PathInteraction), nil)
	if status != http.StatusMethodNotAllowed || hdr.Get("Allow") != "GET, POST" {
		t.Errorf("DELETE on the consent page: %d, Allow %q", status, hdr.Get("Allow"))
	}
}

func TestPersonServerHeadlessApproval(t *testing.T) {
	h := newHarness(t, Config{Consent: ConsentManual})
	agent, loc, code := h.pendingAuthToken()

	status, hdr, _ := h.page(http.MethodGet, h.url(RolePS, PathApprove+"?code="+code), nil)
	if status != http.StatusMethodNotAllowed || hdr.Get("Allow") != http.MethodPost {
		t.Errorf("GET approve: %d, Allow %q", status, hdr.Get("Allow"))
	}
	status, _, body := h.page(http.MethodPost, h.url(RolePS, PathApprove+"?code=ZZZZ-ZZZZ"), url.Values{})
	if status != http.StatusBadRequest || !strings.Contains(body, "error") {
		t.Errorf("unknown code: %d %s", status, body)
	}
	status, _, body = h.page(http.MethodPost, h.url(RolePS, PathApprove+"?code="+url.QueryEscape(code)), url.Values{})
	if status != http.StatusOK || !strings.Contains(body, `"approved"`) {
		t.Fatalf("approve: %d %s", status, body)
	}
	status, _, res := h.call(http.MethodGet, loc, map[string]string{HeaderPresent: PresentAgent, HeaderToken: agent}, nil)
	want(t, "poll after approval", status, http.StatusOK, res)
	// A code approves once.
	status, _, body = h.page(http.MethodPost, h.url(RolePS, PathApprove+"?code="+url.QueryEscape(code)), url.Values{})
	if status != http.StatusBadRequest {
		t.Errorf("second approval with the same code: %d %s", status, body)
	}
}

func TestResourceConsentPage(t *testing.T) {
	h := newHarness(t, Config{Consent: ConsentManual})
	auth := map[string]string{HeaderToken: h.agentToken()}
	status, hdr, body := h.call(http.MethodGet, h.url(RoleResource, "/api/data"), auth, nil)
	want(t, "data", status, http.StatusAccepted, body)
	loc, code := hdr.Get("Location"), between(hdr.Get("AAuth-Requirement"), `code="`, `"`)

	status, _, page := h.page(http.MethodGet, h.url(RoleResource, PathInteraction+"?code="+url.QueryEscape(code)), nil)
	if status != http.StatusOK || !strings.Contains(page, code) || !strings.Contains(page, "read your data") {
		t.Fatalf("resource consent page %d:\n%s", status, page)
	}
	status, _, page = h.page(http.MethodPost, h.url(RoleResource, PathInteraction), url.Values{"code": {"not a code"}})
	if status != http.StatusBadRequest || !strings.Contains(page, "Not approved") {
		t.Fatalf("bad code %d:\n%s", status, page)
	}
	status, _, page = h.page(http.MethodPost, h.url(RoleResource, PathInteraction), url.Values{"code": {code}})
	if status != http.StatusOK || !strings.Contains(page, "Approved") {
		t.Fatalf("approve %d:\n%s", status, page)
	}
	status, rh, body := h.call(http.MethodGet, loc, auth, nil)
	want(t, "poll after approval", status, http.StatusOK, body)
	session := rh.Get("AAuth-Access")
	if session == "" {
		t.Fatal("no session token after approval")
	}

	// The session token serves later requests, presented either way.
	for _, hdrs := range []map[string]string{
		{HeaderToken: auth[HeaderToken], "Authorization": "AAuth " + session},
		{HeaderToken: auth[HeaderToken], "AAuth-Access": session},
	} {
		status, _, body = h.call(http.MethodGet, h.url(RoleResource, "/api/data"), hdrs, nil)
		want(t, "data with the session token", status, http.StatusOK, body)
	}
	status, _, body = h.call(http.MethodGet, h.url(RoleResource, "/api/data"),
		map[string]string{HeaderToken: auth[HeaderToken], "Authorization": "AAuth not-a-session"}, nil)
	want(t, "unknown session", status, http.StatusUnauthorized, body)

	status, hdr, _ = h.page(http.MethodPut, h.url(RoleResource, PathInteraction), nil)
	if status != http.StatusMethodNotAllowed || hdr.Get("Allow") != "GET, POST" {
		t.Errorf("PUT on the consent page: %d, Allow %q", status, hdr.Get("Allow"))
	}
	status, hdr, _ = h.page(http.MethodGet, h.url(RoleResource, PathApprove), nil)
	if status != http.StatusMethodNotAllowed || hdr.Get("Allow") != http.MethodPost {
		t.Errorf("GET approve: %d, Allow %q", status, hdr.Get("Allow"))
	}
	status, _, _ = h.page(http.MethodPost, h.url(RoleResource, PathApprove+"?code=ZZZZ-ZZZZ"), url.Values{})
	if status != http.StatusBadRequest {
		t.Errorf("unknown code at the headless endpoint: %d", status)
	}
}

func TestResourceRefusesAgentsThatCannotInvolveThePerson(t *testing.T) {
	h := newHarness(t, Config{Consent: ConsentManual})
	// The signing helper declares interaction by default; send none.
	status, _, body := h.call(http.MethodGet, h.url(RoleResource, "/api/data"),
		map[string]string{HeaderToken: h.agentToken(), HeaderCapabilitiesOverride: ""}, nil)
	want(t, "data without the interaction capability", status, http.StatusForbidden, body)
}
