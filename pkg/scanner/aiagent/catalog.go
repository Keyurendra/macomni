package aiagent

import (
	"encoding/json"
	"os"
)

type Catalog struct {
	Version int     `json:"version"`
	Agents  []Agent `json:"agents"`
}

type Agent struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Category      string         `json:"category"`
	Platforms     []string       `json:"platforms"`
	Installations []Installation `json:"installations"`
}

type Installation struct {
	Signals Signals `json:"signals"`
}

type Signals struct {
	Packages    []string `json:"packages"`
	Executables []string `json:"executables"`
	Paths       []string `json:"paths"`
}

type PackageSignal struct {
	Name     string
	Version  string
	PURL     string
	FilePath string
}

func LoadCatalog(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var catalog Catalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, err
	}

	return &catalog, nil
}
