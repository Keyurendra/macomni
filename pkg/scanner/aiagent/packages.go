package aiagent

import "github.com/aquasecurity/trivy/pkg/types"

func PackageSignalsFromTrivyResults(results types.Results) []PackageSignal {
	var signals []PackageSignal

	for _, result := range results {
		for _, pkg := range result.Packages {
			signal := PackageSignal{
				Name:     pkg.Name,
				Version:  pkg.Version,
				FilePath: pkg.FilePath,
			}

			if pkg.Identifier.PURL != nil {
				signal.PURL = pkg.Identifier.PURL.String()
			}

			signals = append(signals, signal)
		}
	}

	return signals
}
