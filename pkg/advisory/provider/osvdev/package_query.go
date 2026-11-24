package osvdev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bgriddaluru/gocve/pkg/models"
)

type batchQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

// PackageBatcher yields consecutive groups of at most 1000 packages.
type PackageBatcher struct {
	packages []models.Package
	next     int
}

func NewPackageBatcher(packages []models.Package) *PackageBatcher {
	return &PackageBatcher{packages: packages}
}

// Next returns the next batch, or nil when exhausted. The slice shares the input's storage.
func (b *PackageBatcher) Next() []models.Package {
	if b.next >= len(b.packages) {
		return nil
	}
	start := b.next
	b.next += min(maxBatchSize, len(b.packages)-start)
	return b.packages[start:b.next]
}

type batchResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

func (c *Client) QueryPackageVulnerabilities(ctx context.Context,
	packages []models.Package) (map[string]*models.PackageVulnerability, error) {

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, pkg := range packages {
		if strings.TrimSpace(pkg.Path) == "" || strings.TrimSpace(pkg.Version) == "" {
			return nil, fmt.Errorf("query packages: module path and version must not be empty")
		}
	}

	vulns := make(map[string]*models.PackageVulnerability)
	batcher := NewPackageBatcher(packages) // Create a batcher to yield consecutive groups of at most 1000 packages.
	for batch := batcher.Next(); len(batch) > 0; batch = batcher.Next() {
		queries := getBatchQueryFromPackages(batch)

		results, err := c.queryPaginatedBatch(ctx, queries)
		if err != nil {
			return nil, fmt.Errorf("query packages: %w", err)
		}
		for i, result := range results {
			for _, vuln := range result.Vulns {
				if vuln.ID == "" {
					return nil, fmt.Errorf("query packages: empty vulnerability ID")
				}
				key := fmt.Sprintf("%s@%s", queries[i].Package.Name, queries[i].Version)
				if _, ok := vulns[key]; !ok {
					vulns[key] = &models.PackageVulnerability{
						PackageName:      queries[i].Package.Name,
						InstalledVersion: queries[i].Version,
						VulnSummary:      make(map[string]*models.PackageVulnerabilitySummary),
					}
				}
				vulnEntry := vulns[key]
				vulnEntry.VulnSummary[vuln.ID] = &models.PackageVulnerabilitySummary{
					ID:      vuln.ID,
					Aliases: []string{vuln.ID},
				}
			}
		}
	}

	return vulns, nil
}

// Reference: https://google.github.io/osv.dev/post-v1-querybatch/
// Pagination for the querybatch request may return results with a next_page_token for only a few of the total queries. In this situation, you will need to run additional requests for those specific queries to see the remaining results.
// For the v1/querybatch endpoint pagination will occur when at least one of the following conditions are met:
// 1. An individual query within the queryset returns more than 1,000 vulnerabilities
// 2. The entire queryset returns more than 3,000 vulnerabilities total
func (c *Client) queryPaginatedBatch(ctx context.Context, queries []batchQuery) ([]batchResult, error) {
	results := make([]batchResult, len(queries))
	indices := make([]int, len(queries))
	for i := range indices {
		indices[i] = i
	}
	for len(queries) > 0 {
		batchResults, err := c.queryBatch(ctx, queries)
		if err != nil {
			return nil, err
		}
		paginatedQueries := make([]batchQuery, 0)
		paginatedIndices := make([]int, 0)
		for i, result := range batchResults {
			// Continuation requests contain only queries that still have pages.
			index := indices[i]
			results[index].Vulns = append(results[index].Vulns, result.Vulns...)
			if result.NextPageToken != "" {
				query := queries[i]
				if result.NextPageToken == query.PageToken {
					return nil, fmt.Errorf("query packages: repeated pagination token")
				}
				query.PageToken = result.NextPageToken
				paginatedQueries = append(paginatedQueries, query)
				paginatedIndices = append(paginatedIndices, index)
			}
		}
		queries = paginatedQueries
		indices = paginatedIndices
	}
	return results, nil
}

func (c *Client) queryBatch(ctx context.Context, queries []batchQuery) ([]batchResult, error) {

	payload, err := json.Marshal(struct {
		Queries []batchQuery `json:"queries"`
	}{Queries: queries})

	if err != nil {
		return nil, fmt.Errorf("encode OSV request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, queryBatchURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error: Sending OSV request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return nil, fmt.Errorf("Error: OSV returned HTTP %d; read error response: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("Error: OSV returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var response struct {
		Results []batchResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}
	if len(response.Results) != len(queries) {
		return nil, fmt.Errorf("OSV returned %d results for %d queries", len(response.Results), len(queries))
	}
	return response.Results, nil
}

func getBatchQueryFromPackages(packages []models.Package) []batchQuery {
	queries := make([]batchQuery, len(packages))
	for i, pkg := range packages {
		queries[i].Package.Name = pkg.Path
		queries[i].Package.Ecosystem = "Go"
		queries[i].Version = pkg.Version
	}
	return queries
}
