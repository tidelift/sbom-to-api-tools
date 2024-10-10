package main

//go:generate oapi-codegen --package=tidelift_api_gen -generate=types -include-tags Packages,Releases,Vulnerabilities -o ../../internal/tidelift-api-gen/tidelift.gen.go https://tidelift.com/api/depci/subscriber-api.json

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/package-url/packageurl-go"
	log "github.com/sirupsen/logrus"
	cyclonedx "github.com/tidelift/tidelift-sbom-info/internal/cyclonedx"
	api "github.com/tidelift/tidelift-sbom-info/internal/tidelift-api-gen"
	utils "github.com/tidelift/tidelift-sbom-info/internal/utils"
)

type ViolationRow struct {
	Project		string	`json:"project"`
	ExternalIdentifier	string	`json:"external_identifier"`
	Branch		string	`json:"branch"`
	Catalog		string	`json:"catalog"`
	Groups		string	`json:"groups"`
	ViolationType	string	`json:"violation_type"`
	DirectPackagePlatform	string	`json:"direct_package_platform"`
	DirectPackageName	string	`json:"direct_package_name"`
	DirectPackageVersion	string	`json:"direct_package_version"`
	DirectPackagePublishedAt	string	`json:"direct_package_version_published_at"`
	DirectPurl	string	`json:"direct_purl"`
	ViolatingPackagePlatform	string	`json:"violating_package_platform"`
	ViolatingPackageName	string	`json:"violating_package_name"`
	ViolatingPackageVersion	string	`json:"violating_package_version"`
	ViolatingPackagePublishedAt	string	`json:"violating_package_version_published_at"`
	ViolatingPurl	string	`json:"violating_purl"`
	ViolationFirstIntroducedAt	string	`json:"violation_first_introduced_at"`
	DependencyChain	string	`json:"dependency_chain"`
	DependencyScope	string	`json:"dependency_scope"`
	DependencyType	string	`json:"dependency_type"`
	Action	string	`json:"action"`
	ActionStatus	string	`json:"action_status"`
	ActionRecommendation	string	`json:"action_recommendation"`
	RecommendedDependencyChain	string	`json:"recommended_dependency_chanin"`
	ViolationTitle	string	`json:"violation_title"`
	ViolationDescription	string	`json:"violation_description"`
	ViolationAllowed	bool	`json:"violation_allowed"`
        ViolationDetails interface{} `json:"violation_details"`
	ReportDate		string 	`json:"report_date"`
}

func main() {
	var debug bool
	var outputFile string

	flag.BoolVar(&debug, "debug", false, "Show debug logging")
	flag.StringVar(&outputFile, "output", "", "Write output to a file (defaults to stdout)")

	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Display a JSON file containing violations from Tidelift for the packages in an SBOM.")
		fmt.Fprintln(flag.CommandLine.Output(), "")
		fmt.Fprintln(flag.CommandLine.Output(), "Usage:")
		fmt.Fprintln(flag.CommandLine.Output(), "  tidelift-sbom-reporter [SOURCE]")
		fmt.Fprintln(flag.CommandLine.Output(), "")
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")
		flag.PrintDefaults()
	}

	flag.Parse()

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

	name, purls, err := cyclonedx.SupportedPurlsFromBomFile(flag.Arg(0))
	if err != nil {
		log.Fatalf("Error: %s", err)
	}

	if name == "" {
		name = flag.Arg(0)
	}

	releaseInfo, missingReleases := utils.GetReleaseInfo(purls)

	if len(missingReleases) > 0 {
		log.Debug(fmt.Sprintf("Unable to look up %d releases (may be internal packages)", len(missingReleases)))
	}

	if err := writeViolationsReport(outputFile, purls, releaseInfo, name); err != nil {
		log.Fatalf("Error: %s", err)
	}
}

func writeViolationsReport(outputFile string, purls []packageurl.PackageURL, releaseInfo []api.ReleaseDetail, name string) error {
	var violations []ViolationRow

	timestr := time.Now().Format(time.RFC3339)
	
	for _, purl := range purls {
		releasePurlString := purl.ToString()
		for _, r := range releaseInfo {
			if *r.Purl == releasePurlString {
				if len(*r.Violations) == 0 {
					break
				}
				for _, violation := range *r.Violations {
					v := ViolationRow {
						Project: name,
						ExternalIdentifier: "",
						Branch: "",
						Catalog: "",
						Groups: "",
						ViolationType: *violation.CatalogStandard,
						DirectPackagePlatform: *r.Platform,
						DirectPackageName: *r.Name,
						DirectPackageVersion: *r.Version,
						DirectPackagePublishedAt: *r.PublishedAt,
						DirectPurl: releasePurlString,
						ViolatingPackagePlatform: *r.Platform,
						ViolatingPackageName: *r.Name,	
						ViolatingPackageVersion: *r.Version,
						ViolatingPackagePublishedAt: *r.PublishedAt,
						ViolatingPurl: releasePurlString,
						ViolationFirstIntroducedAt: "",
						DependencyChain: "",
						DependencyScope: "lockfile",
						DependencyType: "",
						RecommendedDependencyChain: "",
						ViolationTitle: *violation.Title,
						ViolationDescription: "",
						ViolationAllowed: false,
						ReportDate: timestr,
					}
					switch *violation.CatalogStandard {
						case "vulnerabilities":
							v.ViolationDetails = violation.AdditionalProperties["vulnerability"]
						case "deprecation":
							v.ViolationDetails = violation.AdditionalProperties["deprecation"]
						case "up_to_date":
							v.ViolationDetails = violation.AdditionalProperties["up_to_date"]
						case "prereleases":
							v.ViolationDetails = nil
						case "eol_packages":
							v.ViolationDetails = violation.AdditionalProperties["eol_package"]
						default:
							log.Debug(fmt.Sprintf("skipping violation for %s", *violation.CatalogStandard))
							continue // don't put other violations in the report
					}
					if r.NearestRecommendedRelease != nil {
						action_text := fmt.Sprintf("Upgrade %s from %s to %s", *r.Name, *r.Version, *r.NearestRecommendedRelease.Version)
						v.ActionRecommendation = action_text
						v.Action = action_text
						v.ActionStatus = "direct_upgrade"
					} else {
						v.ActionRecommendation = ""
						v.Action = "There is no available upgrade that fixes this issue. To avoid this, you may need to use a different package."
						v.ActionStatus = "no_upgrade_path"
					}
					violations = append(violations, v)
				}
			}
		}
	}

	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		jsonStr, err := json.Marshal(violations)
		if err != nil {
			return err
		}
		_, err = f.Write(jsonStr)
		if err != nil {
			return err
		}
		f.Close()
	} else {
		jsonStr, err := json.MarshalIndent(violations, "", "  ")
		if err != nil {
			return err
		}
		fmt.Print(string(jsonStr))
	}

	return nil
}
