package walkthrough_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	regionNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	markerPattern     = regexp.MustCompile(`pidl:(begin|end) ([A-Za-z0-9][A-Za-z0-9_.-]*)`)
	catalogPattern    = regexp.MustCompile(`^//\t([a-z0-9][a-z0-9.-]*)\s+\S`)
)

// catalog returns the region names listed in doc.go.
func catalog(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		if m := catalogPattern.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
	}
	return names
}

// TestRegions checks that every region in doc.go is marked exactly once,
// is not empty, and that no unlisted region exists, so documentation that
// quotes regions by name keeps working.
func TestRegions(t *testing.T) {
	listed := map[string]bool{}
	for _, name := range catalog(t) {
		if !regionNamePattern.MatchString(name) {
			t.Errorf("region name %q", name)
		}
		if listed[name] {
			t.Errorf("region %q listed twice in doc.go", name)
		}
		listed[name] = true
	}
	if len(listed) == 0 {
		t.Fatal("doc.go lists no regions")
	}

	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	type span struct{ begins, ends, lines int }
	found := map[string]*span{}
	for _, f := range files {
		if f == "regions_test.go" {
			continue
		}
		data, err := os.ReadFile(f) // #nosec G304 -- files of this package
		if err != nil {
			t.Fatal(err)
		}
		open := map[string]bool{}
		for _, line := range strings.Split(string(data), "\n") {
			m := markerPattern.FindStringSubmatch(line)
			if m == nil {
				for name := range open {
					if strings.TrimSpace(line) != "" {
						found[name].lines++
					}
				}
				continue
			}
			s := found[m[2]]
			if s == nil {
				s = &span{}
				found[m[2]] = s
			}
			switch m[1] {
			case "begin":
				s.begins++
				open[m[2]] = true
			case "end":
				if !open[m[2]] {
					t.Errorf("%s: region %q ends before it begins", f, m[2])
				}
				s.ends++
				delete(open, m[2])
			}
		}
		for name := range open {
			t.Errorf("%s: region %q has no end", f, name)
		}
	}

	var names []string
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := found[name]
		switch {
		case !listed[name]:
			t.Errorf("region %q is not listed in doc.go", name)
		case s.begins != 1 || s.ends != 1:
			t.Errorf("region %q has %d begin and %d end markers, want 1 each", name, s.begins, s.ends)
		case s.lines == 0:
			t.Errorf("region %q is empty", name)
		}
	}
	for name := range listed {
		if found[name] == nil {
			t.Errorf("region %q is listed in doc.go but not marked", name)
		}
	}
}
