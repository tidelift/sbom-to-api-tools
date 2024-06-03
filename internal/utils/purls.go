package utils

import (
	"strings"

	"github.com/package-url/packageurl-go"
	"golang.org/x/exp/maps"
)

var purlTypeToPlatform = map[string]string{
	"cargo":    "cargo",
	"composer": "packagist",
	"gem":      "rubygems",
	"golang":   "go",
	"maven":    "maven",
	"npm":      "npm",
	"nuget":    "nuget",
	"pypi":     "pypi",
}

var SupportedPurlTypes = maps.Keys(purlTypeToPlatform)

type PackageRelease struct {
	Platform string `json:"platform"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Purl     string
}

func ReleasePurlToPackagePurl(purl packageurl.PackageURL) packageurl.PackageURL {
	return *packageurl.NewPackageURL(purl.Type, purl.Namespace, purl.Name, "", nil, "")
}

func TideliftPlatformFromPurl(purl packageurl.PackageURL) string {
	return purlTypeToPlatform[purl.Type]
}

func TideliftPackageNameFromPurl(purl packageurl.PackageURL) string {
	if purl.Namespace == "" {
		return purl.Name
	}
	if purl.Type == "maven" {
		return strings.Join([]string{purl.Namespace, purl.Name}, ":")
	} else {
		return strings.Join([]string{purl.Namespace, purl.Name}, "/")
	}
}
