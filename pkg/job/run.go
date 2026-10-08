package job

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/aiagent"
	"github.com/accuknox/omniscan/pkg/scanner/clamav"
	"github.com/accuknox/omniscan/pkg/scanner/macos"
	trivyScanner "github.com/accuknox/omniscan/pkg/scanner/trivy"
	"github.com/accuknox/omniscan/pkg/scanner/trivy/container"
	"github.com/accuknox/omniscan/pkg/scanner/trivy/rootfs"
	"github.com/accuknox/omniscan/pkg/scanner/winfs"
	"github.com/accuknox/omniscan/pkg/scanner/winvuln"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

type RunConfig struct {
	Logger                           *slog.Logger
	VulnScan                         bool
	VulnScanDBDir                    string
	AIAgentCatalog                   *aiagent.Catalog
	MacOSVulnScan                    bool
	MacOSFeedURL                     string
	CRISockets                       []string
	ContainerImageScanRemoteFallback bool
	UseExternalTrivy                 bool
	ClusterID                        *int
	ClusterName                      string
	MalwareScan                      bool
	MalwareScanTargetDirectory       string
	UseClamAVDaemon                  bool
	DaemonlessClamavDBDir            string
	OfflineWinVulnScan               bool
	ContainerVulnScan                bool
	ContainerImageScanModeAgentless  bool
}

type Run struct {
	RunConfig
}

type RunResult struct {
	OS                     string
	MalwareScanError       error
	VulnScanError          error
	ContainerVulnScanError error
	ArtifactPublishError   error
}

func NewRun(c RunConfig) Run {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return Run{RunConfig: c}
}

func enrichAIAgentDetections(
	finding *trivyScanner.Result,
	catalog *aiagent.Catalog,
	roots []string,
	osType string,
) {
	if finding == nil || catalog == nil {
		return
	}

	packages := aiagent.PackageSignalsFromTrivyResults(finding.Results)
	finding.AIAgentDetections = aiagent.Detect(catalog, roots, packages, osType)
}

func offlineWindowsTRResult(windowsFinding *winvuln.Result) (*trivyScanner.Result, error) {
	if windowsFinding == nil || windowsFinding.ScanResult == nil {
		return nil, errors.New("offline Windows scan result is empty")
	}

	return &trivyScanner.Result{
		SchemaVersion: 2,
		CreatedAt:     time.Now().UTC(),
		ArtifactName:  windowsFinding.VMUri,
		ArtifactType:  "rootfs",
		Metadata: trivyScanner.Metadata{
			OS:      &ftypes.OS{Family: ftypes.OSType("windows"), Name: windowsFinding.ScanResult.WindowsVersion},
			VM:      trivyScanner.VMMetadata{URI: windowsFinding.VMUri, Platform: windowsFinding.Platform, OS: windowsFinding.OS},
			Windows: windowsFinding.ScanResult,
		},
		Results: winfs.MSRCResults(windowsFinding),
	}, nil
}

func (r Run) ScanMountPoint(ctx context.Context, os, mount, vmURI, platform string, pub scanner.Publish) (*RunResult, error) {
	if r.MalwareScanTargetDirectory == "" {
		r.MalwareScanTargetDirectory = mount
	}

	result := RunResult{OS: os}
	var aiAgentRoots []string
	if os == "windows" {
		if r.OfflineWinVulnScan {
			aiAgentRoots = []string{mount}
		} else if roots, err := winfs.FixedDrives(); err == nil {
			aiAgentRoots = roots
		}
	} else {
		aiAgentRoots = aiagent.DiscoverRoots(mount, os)
	}
	trackedPub := func(ctx context.Context, f scanner.Findings) error {
		if f == nil {
			return nil
		}
		if tf, ok := f.(*trivyScanner.Result); ok {
			tf.ClusterID = r.ClusterID
			tf.ClusterName = r.ClusterName
			enrichAIAgentDetections(
				tf,
				r.AIAgentCatalog,
				aiAgentRoots,
				os,
			)
		}
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"publishing findings",
			slog.String("data_type", f.DataType()),
			slog.String("target_vm_uri", vmURI),
			slog.String("os", os),
		)
		if err := pub(ctx, f); err != nil {
			result.ArtifactPublishError = errors.Join(result.ArtifactPublishError, err)
			return err
		}
		return nil
	}

	// clamAV supports both windows and linux
	if r.MalwareScan {
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running malware scan",
			slog.String("target_directory", r.MalwareScanTargetDirectory),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)

		finding, err := clamav.
			NewScanner(r.UseClamAVDaemon, r.DaemonlessClamavDBDir).
			Scan(
				ctx,
				r.MalwareScanTargetDirectory,
				vmURI,
				platform,
				os,
			)
		result.MalwareScanError = err
		if err == nil && finding != nil {
			if err := trackedPub(ctx, finding); err != nil {
				return &result, nil
			}
		}
	}

	// windows vuln scan
	if os == "windows" && r.VulnScan {
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running windows vuln scan",
			slog.String("mount_point", mount),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)
		opts := []winvuln.OptFunc{
			winvuln.WithDBPath(filepath.Join(r.VulnScanDBDir, "msrc", "db.sqlite3")),
		}
		if r.OfflineWinVulnScan {
			opts = append(opts, winvuln.WithUseOfflineMode())
		}

		finding, err := winvuln.NewScanner(opts...).Scan(
			ctx,
			mount,
			vmURI,
			platform,
			os,
		)
		result.VulnScanError = err
		if err != nil || finding == nil {
			if err == nil {
				result.VulnScanError = errors.New("windows vulnerability scanner returned no result")
			}
			return &result, nil
		}
		if r.OfflineWinVulnScan {
			windowsFinding, ok := finding.(*winvuln.Result)
			if !ok {
				result.VulnScanError = fmt.Errorf("unexpected offline Windows scan result %T", finding)
				return &result, nil
			}
			converted, err := offlineWindowsTRResult(windowsFinding)
			if err != nil {
				result.VulnScanError = err
				return &result, nil
			}
			if err := trackedPub(ctx, converted); err != nil {
				return &result, nil
			}
			return &result, nil
		}
		r.Logger.LogAttrs(ctx, slog.LevelInfo, "running Windows filesystem vulnerability scan")
		windowsFinding, ok := finding.(*winvuln.Result)
		if !ok {
			result.VulnScanError = fmt.Errorf("unexpected Windows scan result %T", finding)
			return &result, nil
		}
		combined, err := (winfs.Scanner{CacheDir: r.VulnScanDBDir}).Collect(ctx, vmURI, platform, windowsFinding)
		result.VulnScanError = err
		if err == nil {
			if err := trackedPub(ctx, combined); err != nil {
				return &result, nil
			}
		}
		return &result, nil
	}

	if os == "macos" && r.VulnScan && r.MacOSVulnScan {
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running macOS vulnerability scan",
			slog.String("mount_point", mount),
			slog.String("target_vm_uri", vmURI),
		)
		var opts []macos.OptFunc
		if r.MacOSFeedURL != "" {
			opts = append(opts, macos.WithFeedURL(r.MacOSFeedURL))
		}
		if r.VulnScanDBDir != "" {
			opts = append(opts, macos.WithCacheDirectory(r.VulnScanDBDir))
		}
		finding, err := macos.NewScanner(opts...).Scan(
			ctx,
			mount,
			vmURI,
			platform,
			os,
		)
		result.VulnScanError = err
		if err == nil && finding != nil {
			if err := trackedPub(ctx, finding); err != nil {
				return &result, nil
			}
		}
		return &result, nil
	}

	if os == "linux" && r.ContainerVulnScan {
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running container vuln scan",
			slog.String("mount_point", mount),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)

		var opts []container.OptFunc

		if r.VulnScanDBDir != "" {
			opts = append(opts, container.WithCacheDirectory(r.VulnScanDBDir))
		}
		if len(r.CRISockets) > 0 {
			opts = append(opts, container.WithCRISockets(r.CRISockets...))
		}
		if r.ContainerImageScanRemoteFallback {
			opts = append(opts, container.WithRemoteFallback())
		}
		if r.ContainerImageScanModeAgentless {
			opts = append(opts, container.WithMountpoint(mount))
		}

		s, err := container.NewScanner(opts...)
		if err != nil {
			return nil, fmt.Errorf("initializing container vuln scanner: %w", err)
		}

		result.ContainerVulnScanError = s.Scan(
			ctx,
			mount,
			vmURI,
			platform,
			os,
			trackedPub,
		)
	}

	// linux vuln scan
	if os == "linux" && r.VulnScan {
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running vuln scan",
			slog.String("mount_point", mount),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)

		var opts []rootfs.OptFunc
		if r.UseExternalTrivy {
			opts = append(opts, rootfs.WithExternalTrivy())
		}
		if r.VulnScanDBDir != "" {
			opts = append(opts, rootfs.WithCacheDirectory(r.VulnScanDBDir))
		}

		s, err := rootfs.NewScanner(opts...)
		if err != nil {
			return nil, fmt.Errorf("initializing vuln scanner: %w", err)
		}

		finding, err := s.Scan(
			ctx,
			mount,
			vmURI,
			platform,
			os,
		)
		result.VulnScanError = err
		if err == nil && finding != nil {
			if err := trackedPub(ctx, finding); err != nil {
				return &result, nil
			}
		}
	}

	return &result, nil
}
