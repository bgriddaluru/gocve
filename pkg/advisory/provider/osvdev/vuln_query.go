package osvdev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bgriddaluru/gocve/pkg/models"
)

func (c *Client) GetVulnerability(ctx context.Context, vulnId string) (models.OSV, error) {

	if vuln, ok := c.Cache.Get(vulnId); ok {
		return vuln, nil
	}
	url := queryVulnerabilityURL + vulnId
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return models.OSV{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return models.OSV{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return models.OSV{}, nil
		}
		return models.OSV{}, fmt.Errorf("failed to get vulnerability details for %s: %s", vulnId, resp.Status)
	}
	var vulnDetail models.OSV
	if err := json.NewDecoder(resp.Body).Decode(&vulnDetail); err != nil {
		return models.OSV{}, err
	}

	c.Cache.Set(vulnId, vulnDetail)

	return vulnDetail, nil
}
