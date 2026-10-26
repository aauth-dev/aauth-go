package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// HeaderFrom names the role that sent a request inside the sandbox. The
// sandbox's own clients set it; role handlers remove it before serving,
// and it is never covered by a signature.
const HeaderFrom = "X-Sandbox-From"

// maxTraceBody bounds the bytes of a body kept in the trace.
const maxTraceBody = 64 << 10

// Exchange is one request and its response, between two roles.
type Exchange struct {
	Time     time.Time `json:"time"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Request  Message   `json:"request"`
	Response Message   `json:"response"`
}

// Message is an HTTP request or response. Headers keep their order;
// Body is JSON when the body is JSON, and a JSON string otherwise.
type Message struct {
	Method  string          `json:"method,omitempty"`
	URL     string          `json:"url,omitempty"`
	Status  int             `json:"status,omitempty"`
	Headers [][2]string     `json:"headers,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

// Trace keeps the most recent exchanges.
type Trace struct {
	mu   sync.Mutex
	size int
	list []Exchange
}

// NewTrace returns a trace keeping at most size exchanges.
func NewTrace(size int) *Trace { return &Trace{size: size} }

// Add records an exchange, dropping the oldest when full.
func (t *Trace) Add(e Exchange) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.list = append(t.list, e)
	if over := len(t.list) - t.size; over > 0 {
		t.list = append([]Exchange(nil), t.list[over:]...)
	}
}

// Exchanges returns a copy of the recorded exchanges, oldest first.
func (t *Trace) Exchanges() []Exchange {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Exchange{}, t.list...)
}

// Clear removes every exchange.
func (t *Trace) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.list = nil
}

// record wraps a role's handler: it notes who sent each request (from
// HeaderFrom, removed before serving) and records the exchange.
func (t *Trace) record(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from := r.Header.Get(HeaderFrom)
		r.Header.Del(HeaderFrom)
		if from == "" {
			from = "client"
		}
		var reqBody []byte
		if r.Body != nil {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
					writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
					return
				}
				http.Error(w, "reading request body", http.StatusBadRequest)
				return
			}
			if cerr := r.Body.Close(); cerr != nil {
				http.Error(w, "closing request body", http.StatusBadRequest)
				return
			}
			reqBody = b
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		u := *r.URL
		u.Scheme, u.Host = "https", r.Host
		t.Add(Exchange{
			Time: time.Now().UTC(), From: from, To: role,
			Request:  Message{Method: r.Method, URL: u.String(), Headers: orderedHeaders(r.Header), Body: traceBody(reqBody)},
			Response: Message{Status: rec.status, Headers: orderedHeaders(w.Header()), Body: traceBody(rec.body.Bytes())},
		})
	})
}

// serveHTTP answers GET (read) and DELETE (clear) on /sandbox/trace.
func (t *Trace) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, t.Exchanges())
	case http.MethodDelete:
		t.Clear()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// recorder captures a response's status and the first bytes of its body.
type recorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	body        bytes.Buffer
}

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status, r.wroteHeader = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	if room := maxTraceBody - r.body.Len(); room > 0 {
		r.body.Write(b[:min(len(b), room)])
	}
	return r.ResponseWriter.Write(b)
}

// Flush passes flushes through, for long-polled responses.
func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// orderedHeaders lists headers sorted by name, values in order, which is
// as close to wire order as net/http keeps.
func orderedHeaders(h http.Header) [][2]string {
	var out [][2]string
	for _, name := range sortedKeys(h) {
		for _, v := range h[name] {
			out = append(out, [2]string{name, v})
		}
	}
	return out
}

// traceBody keeps a JSON body as JSON and anything else as a string.
func traceBody(b []byte) json.RawMessage {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	if len(b) > maxTraceBody {
		b = b[:maxTraceBody]
	}
	if json.Valid(b) {
		return json.RawMessage(b)
	}
	s, err := json.Marshal(string(b))
	if err != nil {
		return nil
	}
	return s
}
