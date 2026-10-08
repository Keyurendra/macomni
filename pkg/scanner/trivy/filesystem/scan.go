package filesystem

import (
	"context"
	"fmt"
	"os"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func Scan(ctx context.Context, target, cacheDir string) (types.Report, error) {
	if cacheDir == "" {
		var err error
		cacheDir, err = os.UserCacheDir()
		if err != nil {
			return types.Report{}, fmt.Errorf("getting user cache directory: %w", err)
		}
	}

	opts := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			Timeout:  12 * time.Hour,
			CacheDir: cacheDir,
			Quiet:    true,
		},
		CacheOptions: flag.CacheOptions{
			CacheBackend: string(cache.TypeMemory),
		},
		ScanOptions: flag.ScanOptions{
			Scanners:          types.Scanners{types.VulnerabilityScanner},
			DisableTelemetry:  true,
			OfflineScan:       true,
			Target:            target,
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
			PkgTypes: []string{types.PkgTypeLibrary},
			PkgRelationships: []ftypes.Relationship{
				ftypes.RelationshipUnknown,
				ftypes.RelationshipWorkspace,
				ftypes.RelationshipRoot,
				ftypes.RelationshipDirect,
				ftypes.RelationshipIndirect,
			},
		},
		ReportOptions: flag.ReportOptions{
			Format:      types.FormatJSON,
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
		return types.Report{}, fmt.Errorf("initializing filesystem scanner: %w", err)
	}
	defer runner.Close(ctx)

	report, err := runner.ScanFilesystem(ctx, opts)
	if err != nil {
		return types.Report{}, fmt.Errorf("scanning filesystem %q: %w", target, err)
	}
	return report, nil
}
