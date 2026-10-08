package trivy

import (
	"time"

	wintypes "github.com/accuknox/accuknox-windows-scanner/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/accuknox/omniscan/pkg/scanner/aiagent"
)

type Result struct {
	SchemaVersion     int
	CreatedAt         time.Time
	ArtifactName      string
	ArtifactType      string
	ClusterID         *int   `json:"cluster_id,omitempty"`
	ClusterName       string `json:"cluster_name,omitempty"`
	Metadata          Metadata
	Results           types.Results
	AIAgentDetections []aiagent.AgentResult `json:"ai_agent_detections,omitempty"`
}

type Metadata struct {
	Size        int64
	OS          *ftypes.OS
	VM          VMMetadata
	Windows     *wintypes.ScanResult `json:"Windows,omitempty"`
	ImageID     string
	DiffIDs     []string
	RepoTags    []string
	RepoDigests []string
	ImageConfig v1.ConfigFile
	Layers      ftypes.Layers
}

type VMMetadata struct {
	URI      string `json:"uri,omitempty"`
	Platform string `json:"platform,omitempty"`
	OS       string `json:"os,omitempty"`
}

func (r Result) DataType() string {
	return "TR"
}
