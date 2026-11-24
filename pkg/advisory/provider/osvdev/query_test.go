package osvdev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/bgriddaluru/gocve/pkg/models"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testClient(t *testing.T, handle func([]batchQuery) (string, int)) *Client {
	t.Helper()
	return &Client{httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		if req.Method != http.MethodPost || req.URL.String() != queryBatchURL {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
		}
		if req.Header.Get("Content-Type") != "application/json" {
			t.Fatal("missing JSON content type")
		}
		var payload struct {
			Queries []batchQuery `json:"queries"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		body, status := handle(payload.Queries)
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})}}
}

func TestQueryBatchSplitsPackages(t *testing.T) {
	for _, count := range []int{0, 1, 1000, 1001, 2001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			packages := make([]models.Package, count)
			for i := range packages {
				packages[i] = models.Package{Path: fmt.Sprintf("example.com/module%d", i), Version: "v1.2.3"}
			}
			calls, queried := 0, 0
			client := testClient(t, func(queries []batchQuery) (string, int) {
				expectedSize := min(1000, count-queried)
				if len(queries) != expectedSize {
					t.Fatalf("batch size = %d, want %d", len(queries), expectedSize)
				}
				results := make([]string, len(queries))
				for i, query := range queries {
					pkg := packages[queried+i]
					if query.Package.Name != pkg.Path || query.Package.Ecosystem != "Go" ||
						query.Version != pkg.Version || query.PageToken != "" {
						t.Fatalf("unexpected query: %+v", query)
					}
					results[i] = `{"vulns":[{"id":"GO-shared"}]}`
				}
				calls++
				queried += len(queries)
				return `{"results":[` + strings.Join(results, ",") + `]}`, http.StatusOK
			})
			ids, err := client.QueryPackageVulnerabilities(context.Background(), packages)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{}
			if count > 0 {
				want = []string{"GO-shared"}
			}
			if !reflect.DeepEqual(ids, want) || queried != count || calls != (count+999)/1000 {
				t.Fatalf("ids=%v, queried=%d, calls=%d", ids, queried, calls)
			}
		})
	}
}

func TestPackageBatcherNext(t *testing.T) {
	for _, count := range []int{0, 1, 1000, 1001, 2000, 2001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			packages := make([]models.Package, count)
			for i := range packages {
				packages[i] = models.Package{Path: fmt.Sprintf("example.com/module%d", i), Version: "v1.0.0"}
			}
			batcher := NewPackageBatcher(packages)
			offset := 0
			for batch := batcher.Next(); batch != nil; batch = batcher.Next() {
				size := min(1000, count-offset)
				if size == 0 || len(batch) != size {
					t.Fatalf("batch size = %d, want %d", len(batch), size)
				}
				if !reflect.DeepEqual(batch, packages[offset:offset+size]) {
					t.Fatal("batch skipped or reordered packages")
				}
				offset += size
			}
			if offset != count {
				t.Fatalf("returned %d packages, want %d", offset, count)
			}
			for range 2 {
				if batcher.Next() != nil {
					t.Fatal("exhausted batcher must keep returning nil")
				}
			}
		})
	}
}

func TestQueryBatchPagination(t *testing.T) {
	calls := 0
	client := testClient(t, func(queries []batchQuery) (string, int) {
		calls++
		switch calls {
		case 1:
			if len(queries) != 3 {
				t.Fatalf("initial query count: %d", len(queries))
			}
			return `{"results":[{"vulns":[{"id":"GO-A"}],"next_page_token":"page-a"},{"vulns":[{"id":"GO-B"}]},{"next_page_token":"page-c"}]}`, http.StatusOK
		case 2:
			if len(queries) != 2 || queries[0].Package.Name != "example.com/a" ||
				queries[0].PageToken != "page-a" || queries[1].Package.Name != "example.com/c" ||
				queries[1].PageToken != "page-c" || queries[1].Version != "v3.0.0" {
				t.Fatalf("unexpected continuation: %+v", queries)
			}
			return `{"results":[{"vulns":[{"id":"GO-A"},{"id":"GO-C"}]},{"next_page_token":"page-c2"}]}`, http.StatusOK
		case 3:
			if len(queries) != 1 || queries[0].Package.Name != "example.com/c" || queries[0].PageToken != "page-c2" {
				t.Fatalf("unexpected continuation: %+v", queries)
			}
			return `{"results":[{"vulns":[{"id":"GO-D"}]}]}`, http.StatusOK
		default:
			t.Fatal("unexpected extra request")
			return "", 0
		}
	})
	ids, err := client.QueryPackageVulnerabilities(context.Background(), []models.Package{
		{Path: "example.com/a", Version: "v1.0.0"},
		{Path: "example.com/b", Version: "v2.0.0"},
		{Path: "example.com/c", Version: "v3.0.0"},
	})
	if err != nil || !reflect.DeepEqual(ids, []string{"GO-A", "GO-B", "GO-C", "GO-D"}) || calls != 3 {
		t.Fatalf("ids=%v, calls=%d, err=%v", ids, calls, err)
	}
}

func TestQueryBatchErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		status int
		want   string
	}{
		{"http", "rate limited", http.StatusTooManyRequests, "HTTP 429: rate limited"},
		{"json", "{", http.StatusOK, "decode OSV response"},
		{"result count", `{"results":[]}`, http.StatusOK, "0 results for 1 queries"},
		{"missing ID", `{"results":[{"vulns":[{}]}]}`, http.StatusOK, "empty vulnerability ID"},
		{"repeated token", `{"results":[{"next_page_token":"same"}]}`, http.StatusOK, "repeated pagination token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func([]batchQuery) (string, int) { return tc.body, tc.status })
			ids, err := client.QueryPackageVulnerabilities(context.Background(), []models.Package{{Path: "example.com/a", Version: "v1.0.0"}})
			if ids != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ids=%v, err=%v", ids, err)
			}
		})
	}
}

func TestQueryBatchDoesNotReturnPartialResults(t *testing.T) {
	calls := 0
	client := testClient(t, func([]batchQuery) (string, int) {
		calls++
		if calls == 1 {
			return `{"results":[{"vulns":[{"id":"GO-A"}],"next_page_token":"next"}]}`, http.StatusOK
		}
		return "unavailable", http.StatusServiceUnavailable
	})
	ids, err := client.QueryPackageVulnerabilities(context.Background(), []models.Package{{Path: "example.com/a", Version: "v1.0.0"}})
	if err == nil || ids != nil || calls != 2 {
		t.Fatalf("ids=%v, calls=%d, err=%v", ids, calls, err)
	}
}

func TestQueryBatchValidatesInputAndCancellation(t *testing.T) {
	client := testClient(t, func([]batchQuery) (string, int) {
		t.Fatal("unexpected request")
		return "", 0
	})
	for _, pkg := range []models.Package{{Path: "example.com/a"}, {Version: "v1.0.0"}, {Path: " ", Version: "v1.0.0"}} {
		if _, err := client.QueryPackageVulnerabilities(context.Background(), []models.Package{pkg}); err == nil {
			t.Fatalf("accepted invalid package: %+v", pkg)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.QueryPackageVulnerabilities(ctx, []models.Package{{Path: "example.com/a", Version: "v1.0.0"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
