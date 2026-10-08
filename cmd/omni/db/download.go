package db

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/urfave/cli/v3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	vulnDBVersion    = "2"
	javaDBVersion    = "1"
	msrcDBVersion    = "v1"
	clamavDBVersion  = "latest"
	aiagentDBVersion = "v1"
)

var downloadCmd = &cli.Command{
	Name: "download",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:      "destination",
			TakesFile: true,
			Value:     "/var/lib/accuknox-omni/",
			Config:    cli.StringConfig{TrimSpace: true},
		},
		&cli.StringFlag{
			Name:   "vuln-db-repository",
			Value:  "ghcr.io/aquasecurity/trivy-db",
			Config: cli.StringConfig{TrimSpace: true},
		},
		&cli.StringFlag{
			Name:   "java-db-repository",
			Value:  "ghcr.io/aquasecurity/trivy-java-db",
			Config: cli.StringConfig{TrimSpace: true},
		},
		&cli.StringFlag{
			Name:   "msrc-db-repository",
			Value:  "public.ecr.aws/k9v9d5v2/msrc-db",
			Config: cli.StringConfig{TrimSpace: true},
		},
		&cli.StringFlag{
			Name:   "clamav-db-repository",
			Value:  "public.ecr.aws/k9v9d5v2/clamav-db",
			Config: cli.StringConfig{TrimSpace: true},
		},
		&cli.StringFlag{
			Name:   "aiagent-db-repository",
			Value:  "public.ecr.aws/k9v9d5v2/accuknox-omni-aiagent-db",
			Config: cli.StringConfig{TrimSpace: true},
		},
		&cli.BoolFlag{
			Name:  "force",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "plain-http",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "skip-tls-verification",
			Value: false,
		},
		&cli.StringFlag{
			Name:   "username",
			Config: cli.StringConfig{TrimSpace: true},
		},
		&cli.StringFlag{
			Name:   "password",
			Config: cli.StringConfig{TrimSpace: true},
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArgs{
			Name:      "databases",
			Max:       5,
			Min:       1,
			Config:    cli.StringConfig{TrimSpace: true},
			UsageText: "[vuln java msrc clamav aiagent]",
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		databases := slices.Compact(c.StringArgs("databases"))
		if len(databases) == 0 {
			return fmt.Errorf("no database specified")
		}

		vulnDBRepo := c.String("vuln-db-repository")
		javaDBRepo := c.String("java-db-repository")
		msrcDBRepo := c.String("msrc-db-repository")
		clamavDBRepo := c.String("clamav-db-repository")
		aiagentDBRepo := c.String("aiagent-db-repository")
		cacheDir := c.String("destination")
		force := c.Bool("force")
		skipTLSVerification := c.Bool("skip-tls-verification")
		plainHTTP := c.Bool("plain-http")
		username := c.String("username")
		password := c.String("password")

		for _, database := range databases {
			switch database {
			case "vuln":
				needsUpdate, err := needsUpdate(cacheDir, database)
				if err != nil {
					return fmt.Errorf("determining if an update is needed: %w", err)
				}
				if !needsUpdate && !force {
					slog.LogAttrs(
						ctx,
						slog.LevelInfo,
						"vuln db is fairly recent. Skipping...",
					)
					continue
				}

				destination := filepath.Join(cacheDir, "db")
				if err := os.MkdirAll(destination, 0o755); err != nil {
					return fmt.Errorf("creating directory %s: %w", destination, err)
				}

				err = download(ctx, vulnDBRepo, vulnDBVersion, destination, plainHTTP, skipTLSVerification, username, password)
				if err != nil {
					return err
				}

				err = extractTarGz(filepath.Join(destination, "db.tar.gz"))
				if err != nil {
					return fmt.Errorf("extracting downloaded db: %w", err)
				}
			case "java":
				needsUpdate, err := needsUpdate(cacheDir, database)
				if err != nil {
					return fmt.Errorf("determining if an update is needed: %w", err)
				}
				if !needsUpdate && !force {
					slog.LogAttrs(
						ctx,
						slog.LevelInfo,
						"java db is fairly recent. Skipping...",
					)
					continue
				}

				destination := filepath.Join(cacheDir, "java-db")
				if err := os.MkdirAll(destination, 0o755); err != nil {
					return fmt.Errorf("creating directory %s: %w", destination, err)
				}

				err = download(ctx, javaDBRepo, javaDBVersion, destination, plainHTTP, skipTLSVerification, username, password)
				if err != nil {
					return err
				}

				err = extractTarGz(filepath.Join(destination, "javadb.tar.gz"))
				if err != nil {
					return fmt.Errorf("extracting downloaded db: %w", err)
				}
			case "msrc":
				needsUpdate, err := needsUpdate(cacheDir, database)
				if err != nil {
					return fmt.Errorf("determining if an update is needed: %w", err)
				}
				if !needsUpdate && !force {
					slog.LogAttrs(
						ctx,
						slog.LevelInfo,
						"msrc db is fairly recent. Skipping...",
					)
					continue
				}

				dst := filepath.Join(cacheDir, "msrc")
				if err := os.MkdirAll(dst, 0o755); err != nil {
					return fmt.Errorf("creating directory %s: %w", dst, err)
				}

				err = download(ctx, msrcDBRepo, msrcDBVersion, dst, plainHTTP, skipTLSVerification, username, password)
				if err != nil {
					return err
				}
			case "clamav":
				needsUpdate, err := needsUpdate(cacheDir, database)
				if err != nil {
					return fmt.Errorf("determining if an update is needed: %w", err)
				}
				if !needsUpdate && !force {
					slog.LogAttrs(
						ctx,
						slog.LevelInfo,
						"clamav db is fairly recent. Skipping...",
					)
					continue
				}

				dst := filepath.Join(cacheDir, "clamav")
				if err := os.MkdirAll(dst, 0o755); err != nil {
					return fmt.Errorf("creating directory %s: %w", dst, err)
				}

				err = download(ctx, clamavDBRepo, clamavDBVersion, dst, plainHTTP, skipTLSVerification, username, password)
				if err != nil {
					return err
				}

			case "aiagent":
				needsUpdate, err := needsUpdate(cacheDir, database)
				if err != nil {
					return fmt.Errorf("determining if an update is needed: %w", err)
				}
				if !needsUpdate && !force {
					slog.LogAttrs(
						ctx,
						slog.LevelInfo,
						"aiagent db is fairly recent. Skipping...",
					)
					continue
				}

				dst := filepath.Join(cacheDir, "aiagent")
				if err := os.MkdirAll(dst, 0o755); err != nil {
					return fmt.Errorf("creating directory %s: %w", dst, err)
				}

				err = download(
					ctx,
					aiagentDBRepo,
					aiagentDBVersion,
					dst,
					plainHTTP,
					skipTLSVerification,
					username,
					password,
				)
				if err != nil {
					return err
				}

			default:
				slog.LogAttrs(
					ctx,
					slog.LevelError,
					"Unknown database passed...Ignoring",
					slog.String("argument", database),
				)
			}
		}
		return nil
	},
}

func needsUpdate(dir string, typ string) (bool, error) {
	if !fsutils.DirExists(dir) {
		return true, nil
	}
	dbFile := filepath.Join("db", "trivy.db")
	threshold := time.Hour * 24
	if typ == "java" {
		dbFile = filepath.Join("java-db", "trivy-java.db")
		threshold = time.Hour * 24 * 3
	}
	if typ == "msrc" {
		dbFile = filepath.Join("msrc", "db.sqlite3")
	}
	if typ == "clamav" {
		dbFile = filepath.Join("clamav", "main.cvd")
	}

	if typ == "aiagent" {
		dbFile = filepath.Join("aiagent", "aiagentscan.json")
	}

	dbFile = filepath.Join(dir, dbFile)
	info, err := os.Stat(dbFile)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("getting db file info: %w", err)
	}
	return time.Since(info.ModTime()) > threshold, nil
}

func download(ctx context.Context, repo, tag, dst string, plainHTTP, skipTLSVerification bool, username, password string) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: skipTLSVerification,
	}

	remote, err := remote.NewRepository(repo)
	if err != nil {
		return fmt.Errorf("creating repo %s client: %w", repo, err)
	}
	remote.PlainHTTP = plainHTTP

	authClient := &auth.Client{
		Client: &http.Client{
			Transport: transport,
		},
		Cache: auth.NewCache(),
	}
	if username != "" && password != "" {
		authClient.Credential = auth.StaticCredential(remote.Reference.Registry, auth.Credential{
			Username: username,
			Password: password,
		})
	}
	remote.Client = authClient

	target, err := file.New(dst)
	if err != nil {
		return fmt.Errorf("creating oci store: %w", err)
	}

	slog.InfoContext(ctx, "Downloading artifact...", slog.String("repo", repo))

	_, err = oras.Copy(ctx, remote, tag, target, "", oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("pulling DB: %w", err)
	}

	slog.InfoContext(ctx, "Artifact successfully downloaded", slog.String("repo", repo))
	return nil
}

func extractTarGz(src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	baseDir := filepath.Dir(src)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(baseDir, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			fw, err := os.OpenFile(
				target,
				os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
				os.FileMode(hdr.Mode),
			)
			if err != nil {
				return err
			}
			if _, err := io.Copy(fw, tr); err != nil {
				fw.Close()
				return err
			}
			fw.Close()
		}
	}

	return os.Remove(src)
}
