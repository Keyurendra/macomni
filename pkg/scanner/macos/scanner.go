package macos

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/hashicorp/go-version"
	"github.com/mikeschinkel/go-sofafeed/feeds/v1feed"
	"github.com/package-url/packageurl-go"
	"howett.net/plist"

	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/trivy"
)

const systemVersionPath = "System/Library/CoreServices/SystemVersion.plist"

type s struct {
	opts
}

type systemVersion struct {
	ProductName    string `plist:"ProductName"`
	ProductVersion string `plist:"ProductVersion"`
	BuildVersion   string `plist:"ProductBuildVersion"`
}

type fix struct {
	version   *version.Version
	url       string
	exploited bool
}

func NewScanner(fns ...OptFunc) *s {
	o := defaultOpts()
	for _, fn := range fns {
		fn(&o)
	}
	return &s{opts: o}
}

func (s s) Scan(ctx context.Context, mount, vmURI, platform, osType string) (scanner.Findings, error) {
	osv, err := readSystemVersion(mount)
	if err != nil {
		return nil, err
	}

	feed, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}

	purl := packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		"apple",
		"macos",
		osv.ProductVersion,
		packageurl.Qualifiers{{Key: "build", Value: osv.BuildVersion}},
		"",
	)
	pkg := ftypes.Package{
		Name:    "macOS",
		Version: osv.ProductVersion,
		Identifier: ftypes.PkgIdentifier{
			PURL: purl,
		},
	}
	pkg.Identifier.UID = dependency.UID("", pkg)

	vulns, err := findVulnerabilities(
		feed,
		osv.ProductVersion,
		s.feedURL,
		pkg.Identifier,
	)
	if err != nil {
		return nil, err
	}

	report, err := s.scanFS(ctx, mount)
	if err != nil {
		return nil, err
	}

	return &trivy.Result{
		SchemaVersion: report.SchemaVersion,
		CreatedAt:     report.CreatedAt,
		ArtifactName:  report.ArtifactName,
		ArtifactType:  "rootfs",
		Metadata: trivy.Metadata{
			Size: report.Metadata.Size,
			OS: &ftypes.OS{
				Family: ftypes.OSType("macos"),
				Name:   osv.ProductVersion,
			},
			VM: trivy.VMMetadata{
				URI:      vmURI,
				Platform: platform,
				OS:       osType,
			},
		},
		Results: append(trivyTypes.Results{
			{
				Target: fmt.Sprintf(
					"%s %s (%s)",
					osv.ProductName,
					osv.ProductVersion,
					osv.BuildVersion,
				),
				Class:           trivyTypes.ClassOSPkg,
				Type:            ftypes.TargetType("macos"),
				Packages:        []ftypes.Package{pkg},
				Vulnerabilities: vulns,
			},
		}, report.Results...),
	}, nil
}

func (s s) scanFS(ctx context.Context, mount string) (trivyTypes.Report, error) {
	cacheDir := s.cacheDir
	if cacheDir == "" {
		var err error
		cacheDir, err = os.UserCacheDir()
		if err != nil {
			return trivyTypes.Report{}, fmt.Errorf(
				"getting user cache directory: %w",
				err,
			)
		}
	}

	opts := flag.Options{
		DisabledAnalyzers: []analyzer.Type{analyzer.TypePom},
		GlobalOptions: flag.GlobalOptions{
			Timeout:  12 * time.Hour,
			CacheDir: cacheDir,
			Quiet:    true,
		},
		CacheOptions: flag.CacheOptions{
			CacheBackend: string(cache.TypeMemory),
		},
		ScanOptions: flag.ScanOptions{
			Scanners: trivyTypes.Scanners{
				trivyTypes.VulnerabilityScanner,
			},
			DisableTelemetry:  true,
			OfflineScan:       true,
			Target:            mount,
			DetectionPriority: ftypes.PriorityPrecise,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnSeveritySources: []dbTypes.SourceID{"auto"},
		},
		DBOptions: flag.DBOptions{
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
		},
		PackageOptions: flag.PackageOptions{
			PkgTypes: []string{trivyTypes.PkgTypeLibrary},
			PkgRelationships: []ftypes.Relationship{
				ftypes.RelationshipUnknown,
				ftypes.RelationshipRoot,
				ftypes.RelationshipWorkspace,
				ftypes.RelationshipDirect,
				ftypes.RelationshipIndirect,
			},
		},
		ReportOptions: flag.ReportOptions{
			Format:      trivyTypes.FormatJSON,
			ListAllPkgs: true,
			Severities: []dbTypes.Severity{
				dbTypes.SeverityUnknown,
				dbTypes.SeverityLow,
				dbTypes.SeverityMedium,
				dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			},
		},
	}

	runner, err := artifact.NewRunner(ctx, opts, artifact.TargetFilesystem)
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf(
			"initializing filesystem scanner: %w",
			err,
		)
	}
	defer runner.Close(ctx)

	report, err := runner.ScanFilesystem(ctx, opts)
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf(
			"scanning filesystem %q: %w",
			mount,
			err,
		)
	}
	return report, nil
}

func readSystemVersion(root string) (systemVersion, error) {
	path := filepath.Join(root, systemVersionPath)
	f, err := os.Open(path)
	if err != nil {
		return systemVersion{}, fmt.Errorf("opening macos system version: %w", err)
	}

	var osv systemVersion
	decodeErr := plist.NewDecoder(f).Decode(&osv)
	if err := f.Close(); err != nil {
		return systemVersion{}, fmt.Errorf(
			"closing macos system version: %w",
			err,
		)
	}
	if decodeErr != nil {
		return systemVersion{}, fmt.Errorf(
			"decoding macos system version: %w",
			decodeErr,
		)
	}
	if osv.ProductVersion == "" {
		return systemVersion{}, fmt.Errorf("macos product version is empty")
	}
	if osv.BuildVersion == "" {
		return systemVersion{}, fmt.Errorf("macos build version is empty")
	}
	return osv, nil
}

func (s s) fetch(ctx context.Context) (v1feed.Feed, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.feedURL, nil)
	if err != nil {
		return v1feed.Feed{}, fmt.Errorf("creating sofa feed request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "accuknox-omniscan/macos-vulnerability-scanner")

	resp, err := s.client.Do(req)
	if err != nil {
		return v1feed.Feed{}, fmt.Errorf("fetching sofa feed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if err := resp.Body.Close(); err != nil {
			return v1feed.Feed{}, fmt.Errorf(
				"closing sofa feed response: %w",
				err,
			)
		}
		return v1feed.Feed{}, fmt.Errorf("fetching sofa feed: %s", resp.Status)
	}

	var feed v1feed.Feed
	r := io.LimitReader(resp.Body, 16<<20)
	decodeErr := json.NewDecoder(r).Decode(&feed)
	if err := resp.Body.Close(); err != nil {
		return v1feed.Feed{}, fmt.Errorf(
			"closing sofa feed response: %w",
			err,
		)
	}
	if decodeErr != nil {
		return v1feed.Feed{}, fmt.Errorf(
			"decoding sofa feed: %w",
			decodeErr,
		)
	}
	if feed.UpdateHash == "" || len(feed.OSVersions) == 0 {
		return v1feed.Feed{}, fmt.Errorf("invalid sofa feed")
	}
	return feed, nil
}

func findVulnerabilities(feed v1feed.Feed, installed, feedURL string, pkgID ftypes.PkgIdentifier) ([]trivyTypes.DetectedVulnerability, error) {
	current, err := version.NewVersion(installed)
	if err != nil {
		return nil, fmt.Errorf(
			"parsing installed macos version %q: %w",
			installed,
			err,
		)
	}

	fixed := map[string]fix{}
	found := false
	for _, osv := range feed.OSVersions {
		for _, release := range osv.SecurityReleases {
			patched, err := version.NewVersion(release.ProductVersion)
			if err != nil {
				return nil, fmt.Errorf(
					"parsing sofa macos version %q: %w",
					release.ProductVersion,
					err,
				)
			}
			if patched.Segments()[0] != current.Segments()[0] {
				continue
			}
			found = true
			if patched.LessThanOrEqual(current) {
				continue
			}

			for id, exploited := range release.CVEs {
				old, ok := fixed[id]
				if ok {
					if old.version.LessThanOrEqual(patched) {
						old.exploited = old.exploited || exploited
						fixed[id] = old
						continue
					}
					exploited = old.exploited || exploited
				}
				fixed[id] = fix{
					version:   patched,
					url:       release.SecurityInfo,
					exploited: exploited,
				}
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("macos %s is absent from sofa feed", installed)
	}

	ids := make([]string, 0, len(fixed))
	for id := range fixed {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	vulns := make([]trivyTypes.DetectedVulnerability, 0, len(ids))
	for _, id := range ids {
		f := fixed[id]
		vulns = append(vulns, trivyTypes.DetectedVulnerability{
			VulnerabilityID:  id,
			PkgName:          "macOS",
			PkgIdentifier:    pkgID,
			InstalledVersion: installed,
			FixedVersion:     f.version.Original(),
			PrimaryURL:       f.url,
			DataSource: &dbTypes.DataSource{
				ID:   dbTypes.SourceID("apple-sofa"),
				Name: "Apple security releases via MacAdmins SOFA",
				URL:  feedURL,
			},
			Custom: map[string]bool{
				"actively_exploited": f.exploited,
			},
		})
	}
	return vulns, nil
}
