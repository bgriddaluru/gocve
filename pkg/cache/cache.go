package cache

import "github.com/bgriddaluru/gocve/pkg/models"

type Cache struct {
	data map[string]models.OSV
}

func NewCache() *Cache {
	return &Cache{
		data: make(map[string]models.OSV),
	}
}

func (c *Cache) Get(id string) (models.OSV, bool) {
	vuln, ok := c.data[id]
	return vuln, ok
}

func (c *Cache) Set(id string, vuln models.OSV) {
	c.data[id] = vuln
}
