package main

//go:generate oapi-codegen --package=tidelift_api_gen -generate=types -include-tags Packages,Releases,Vulnerabilities -o ../../internal/tidelift-api-gen/tidelift.gen.go https://tidelift.com/api/depci/subscriber-api.json

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"

	"github.com/package-url/packageurl-go"
	log "github.com/sirupsen/logrus"
	cyclonedx "github.com/tidelift/tidelift-sbom-info/internal/cyclonedx"
	api "github.com/tidelift/tidelift-sbom-info/internal/tidelift-api-gen"
	utils "github.com/tidelift/tidelift-sbom-info/internal/utils"
)

// This gets overwritten by goreleaser with the git tag, during a release.
var (
	version = "dev"
)

func main() {
	var debug bool
	var outputFile string
	var printVersion bool

	flag.BoolVar(&debug, "debug", false, "Show debug logging")
	flag.StringVar(&outputFile, "output", "", "Write output to a file (defaults to stdout)")
	flag.BoolVar(&printVersion, "version", false, "Show version information")

	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Display a CSV containing recommendations from Tidelift for the packages in an SBOM.")
		fmt.Fprintln(flag.CommandLine.Output(), "")
		fmt.Fprintln(flag.CommandLine.Output(), "Usage:")
		fmt.Fprintln(flag.CommandLine.Output(), "  tidelift-sbom-analyzer [SOURCE]")
		fmt.Fprintln(flag.CommandLine.Output(), "")
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if printVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if _, keyExists := os.LookupEnv("TIDELIFT_API_KEY"); !keyExists {
		log.Fatalf("Error: TIDELIFT_API_KEY environment variable is required.")
	}

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Error: need to pass cyclonedx file as argument")
		flag.Usage()
		os.Exit(1)
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	purls, err := cyclonedx.SupportedPurlsFromBomFile(flag.Arg(0))
	if err != nil {
		log.Fatalf("Error: %s", err)
	}

	packageInfo, missingPackages := utils.GetPackageInfo(purls)
	releaseInfo, missingReleases := utils.GetReleaseInfo(purls)
	log.Debug(fmt.Sprintf("Unable to look up %d packages and %d releases (may be internal packages)", len(missingPackages), len(missingReleases)))

	if err := writeContentsReport(outputFile, purls, packageInfo, releaseInfo); err != nil {
		log.Fatalf("Error: %s", err)
	}
}

func writeContentsReport(outputFile string, purls []packageurl.PackageURL, packageInfo []api.PackageDetail, releaseInfo []api.ReleaseDetail) error {
	var writer *csv.Writer
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		writer = csv.NewWriter(f)
		defer f.Close()
	} else {
		writer = csv.NewWriter(os.Stdout)
	}

	if err := writer.Write([]string{"platform", "name", "version", "purl", "license", "appears_maintained", "tidelift_recommended", "nearest_recommended_version"}); err != nil {
		return err
	}

	for _, purl := range purls {
		var isRecommended = ""
		var recommendedRelease = ""
		var license = ""
		releasePurlString := purl.ToString()
		pkgPurlString := utils.ReleasePurlToPackagePurl(purl).String()

		for _, r := range releaseInfo {
			if *r.Purl == releasePurlString {
				if r.NearestRecommendedRelease != nil {
					recommendedRelease = string(*r.NearestRecommendedRelease.Version)
				}
				license = *r.License.Expression
				isRecommended = string(*r.TideliftRecommendation)
				break
			}
		}

		var isMaintained = ""
		for _, p := range packageInfo {
			if p.Purl == pkgPurlString {
				isMaintained = string(p.QualityChecks.PackageAppearsMaintained.Status)
				break
			}
		}

		if err := writer.Write([]string{utils.TideliftPlatformFromPurl(purl), utils.TideliftPackageNameFromPurl(purl), purl.Version, releasePurlString, license, isMaintained, isRecommended, recommendedRelease}); err != nil {
			return err
		}
	}

	writer.Flush()
	return nil
}
