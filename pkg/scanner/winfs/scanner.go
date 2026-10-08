package winfs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	wintypes "github.com/accuknox/accuknox-windows-scanner/pkg/types"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/accuknox/omniscan/pkg/scanner/trivy"
	"github.com/accuknox/omniscan/pkg/scanner/trivy/filesystem"
	"github.com/accuknox/omniscan/pkg/scanner/winvuln"
)

type Scanner struct {
	CacheDir   string
	listDrives func() ([]string, error)
	scanDrive  func(context.Context, string, string) (types.Report, error)
}

// Collect produces one VM artifact only after every fixed drive has succeeded.
func (s Scanner) Collect(ctx context.Context, vmURI, platform string, windows *winvuln.Result) (*trivy.Result, error) {
	if windows == nil || windows.ScanResult == nil {
		return nil, errors.New("windows scan result is empty")
	}
	list := s.listDrives
	if list == nil {
		list = fixedDrives
	}
	drives, err := list()
	if err != nil {
		return nil, err
	}
	if len(drives) == 0 {
		return nil, errors.New("no fixed local drives found")
	}

	metadataWindows := *windows.ScanResult
	metadataWindows.MissingKBs = nil
	metadataWindows.MissingKBDetails = nil

	result := &trivy.Result{
		SchemaVersion: 2,
		CreatedAt:     time.Now().UTC(),
		ArtifactName:  vmURI,
		ArtifactType:  "rootfs",
		Metadata: trivy.Metadata{
			OS:      &ftypes.OS{Family: ftypes.OSType("windows"), Name: windows.WindowsVersion},
			VM:      trivy.VMMetadata{URI: vmURI, Platform: platform, OS: "windows"},
			Windows: &metadataWindows,
		},
		Results: MSRCResults(windows),
	}
	scan := s.scanDrive
	if scan == nil {
		scan = filesystem.Scan
	}
	for _, drive := range drives {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		report, err := scan(ctx, drive, s.CacheDir)
		if err != nil {
			return nil, fmt.Errorf("drive %s: %w", drive, err)
		}
		result.Metadata.Size += report.Metadata.Size
		for _, finding := range report.Results {
			finding.Target = absoluteTarget(drive, finding.Target)
			result.Results = append(result.Results, finding)
		}
	}
	return result, nil
}

func absoluteTarget(drive, target string) string {
	target = strings.ReplaceAll(target, "/", `\`)
	if len(target) >= 3 && target[1] == ':' && target[2] == '\\' {
		return target
	}
	return strings.TrimRight(drive, `\`) + `\` + strings.TrimLeft(target, `\`)
}

func MSRCResults(windows *winvuln.Result) types.Results {
	var results types.Results
	add := func(location, name, version, kb, kind string, cves []wintypes.CVE) {
		if len(cves) == 0 {
			return
		}
		result := types.Result{Target: location, Class: types.ClassOSPkg, Type: ftypes.TargetType("windows-msrc")}
		for _, cve := range cves {
			v := types.DetectedVulnerability{
				VulnerabilityID: cve.ID, PkgName: name, InstalledVersion: version,
				FixedVersion: kb, PrimaryURL: cve.URL,
				Custom: map[string]string{"updateKind": kind, "kb": kb},
				Vulnerability: dbtypes.Vulnerability{
					Title:       cve.Title,
					Description: cve.Description,
					Severity:    strings.ToUpper(cve.Severity), //nolint:staticcheck // Retain the TR Severity field for existing report consumers.
					CVSS:        dbtypes.VendorCVSS{"nvd": {V3Score: cve.CVSS, V3Vector: cve.Vector}},
				},
			}
			if cve.URL != "" {
				v.References = []string{cve.URL}
			}
			result.Vulnerabilities = append(result.Vulnerabilities, v)
		}
		results = append(results, result)
	}
	for _, update := range windows.MissingSoftwareUpdates {
		add(update.Name+"@"+update.Version, update.Name, update.Version, update.KB, "software", update.CVEs)
	}
	for _, update := range windows.MissingKBDetails {
		add("Windows Security Update ("+update.KB+")", "", "", update.KB, "kb", update.CVEs)
	}
	return results
}
