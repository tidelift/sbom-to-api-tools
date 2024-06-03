package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"

	requests "github.com/carlmjohnson/requests"
	"github.com/package-url/packageurl-go"
	log "github.com/sirupsen/logrus"
	api "github.com/tidelift/tidelift-sbom-info/internal/tidelift-api-gen"
)

const CHUNK_SIZE = 500

type packageLookupResponse struct {
	Packages       []api.PackageDetail `json:"packages"`
	MissingResults []api.Package       `json:"missing_results"`
}

type purlLookupRequest struct {
	Purls []string `json:"purls"`
}

type releaseLookupResponse struct {
	Releases       []api.ReleaseDetail `json:"releases"`
	MissingResults []PackageRelease    `json:"missing_results"`
}

func GetPackageInfo(purls []packageurl.PackageURL) ([]api.PackageDetail, []api.Package) {
	var packageInfo []api.PackageDetail
	var missingPackages []api.Package

	for start := 0; start < len(purls); start += CHUNK_SIZE {
		purlStrings := chunkOfPurlStrings(purls, start, CHUNK_SIZE)

		var packageRsp packageLookupResponse
		if err := requests.URL("https://api.tidelift.com/external-api/v1/packages/lookup").
			BodyJSON(purlLookupRequest{purlStrings}).
			ToJSON(&packageRsp).
			ContentType("application/json").
			// TODO: could use the full auth setup that we do in the tidelift cli
			Header("Authorization", "Bearer "+os.Getenv("TIDELIFT_API_KEY")).
			Fetch(context.Background()); err != nil {
			log.Warn(fmt.Sprintf("problem fetching package info %s ", err))
		}
		packageInfo = append(packageInfo, packageRsp.Packages...)
		missingPackages = append(missingPackages, packageRsp.MissingResults...)
	}
	return packageInfo, missingPackages
}

func GetReleaseInfo(purls []packageurl.PackageURL) ([]api.ReleaseDetail, []PackageRelease) {
	var releaseInfo []api.ReleaseDetail
	var missingReleases []PackageRelease
	for start := 0; start < len(purls); start += CHUNK_SIZE {
		purlStrings := chunkOfPurlStrings(purls, start, CHUNK_SIZE)

		var releaseRsp releaseLookupResponse
		if err := requests.URL("https://api.tidelift.com/external-api/v1/releases/lookup").
			BodyJSON(purlLookupRequest{purlStrings}).
			ToJSON(&releaseRsp).
			ContentType("application/json").
			// TODO: could use the full auth setup that we do in the tidelift cli
			Header("Authorization", "Bearer "+os.Getenv("TIDELIFT_API_KEY")).
			Fetch(context.Background()); err != nil {
			log.Warn(fmt.Sprintf("problem fetching package info %s ", err))
		}

		releaseInfo = append(releaseInfo, releaseRsp.Releases...)
		missingReleases = append(missingReleases, releaseRsp.MissingResults...)
	}
	return releaseInfo, missingReleases
}

func DebugJsonPrint(toPrint any) {
	jsonStr, err := json.MarshalIndent(toPrint, "", " ")
	if err != nil {
		panic(err)
	}
	log.Debug(string(jsonStr))
}

func chunkOfPurlStrings(purls []packageurl.PackageURL, start int, chunk_size int) []string {
	end := int(math.Min(float64(start+chunk_size), float64(len(purls))))
	var purlStrings []string
	for _, purl := range purls[start:end:end] {
		purlStrings = append(purlStrings, purl.ToString())
	}
	return purlStrings
}
