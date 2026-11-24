package osvdev

import (
	"net/http"

	"github.com/bgriddaluru/gocve/pkg/cache"
	"github.com/bgriddaluru/gocve/pkg/utils/logger"
)

type Client struct {
	httpClient *http.Client
	logger     *logger.Logger
	Cache      *cache.Cache
}

func NewClient(logger *logger.Logger, cache *cache.Cache) *Client {
	return &Client{
		httpClient: &http.Client{},
		logger:     logger,
		Cache:      cache,
	}
}
