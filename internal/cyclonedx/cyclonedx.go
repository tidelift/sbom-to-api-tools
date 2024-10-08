// This has all of the code to read a cyclonedx sbom and convert to a list of
// platform, name, version tuples as needed by the current Tidelift APIs

package cyclonedx

import (
	"fmt"
	"os"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	log "github.com/sirupsen/logrus"
	"github.com/tidelift/tidelift-sbom-info/internal/utils"
)

func SupportedPurlsFromBomFile(filename string) (string, []packageurl.PackageURL, error) {
	bom, err := decodeCyclonedx(filename)
	if err != nil {
		return "", nil, err
	}

	purls, err := extractSupportedPurls(bom)
	if err != nil {
		return "", nil, err
	}

	if bom.Metadata == nil || bom.Metadata.Component == nil {
		log.Warn("CycloneDX file does not have any metadata")
		return "", purls, nil
	}
	return bom.Metadata.Component.Name, purls, nil
}

func decodeCyclonedx(filename string) (*cdx.BOM, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(file, cdx.BOMFileFormatJSON)
	if err = decoder.Decode(bom); err != nil {
		return nil, err
	}
	return bom, nil
}

func extractSupportedPurls(bom *cdx.BOM) ([]packageurl.PackageURL, error) {
	purlMap := map[string]packageurl.PackageURL{}

	if bom.Components == nil {
		log.Warn("CycloneDX file does not have any components")
		return make([]packageurl.PackageURL, 0), nil
	}

	for _, comp := range *bom.Components {
		if comp.Type != "library" {
			logBadPurl(comp, "Skipping non-library component in SBOM")
			continue
		}
		if comp.PackageURL == "" {
			logBadPurl(comp, "Skipping component in SBOM without purl")
			continue
		}

		purl, err := packageurl.FromString(comp.PackageURL)
		if err != nil {
			logBadPurl(comp, "Skipping malformed purl")
			continue
		}
		if !slices.Contains(utils.SupportedPurlTypes, purl.Type) {
			logBadPurl(comp, "Skipping component in SBOM with unsupported purl type")
			continue
		}

		purlMap[purl.String()] = purl
	}

	purls := make([]packageurl.PackageURL, 0, len(purlMap))

	for _, purl := range purlMap {
		purls = append(purls, purl)
	}

	log.Debug(fmt.Sprintf("Found %d purls\n", len(purls)))

	return purls, nil
}

func logBadPurl(comp cdx.Component, msg string) {
	log.WithFields(log.Fields{
		"type": comp.Type,
		"name": comp.Name,
		"purl": comp.PackageURL,
	}).Debug(msg)
}
