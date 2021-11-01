package convert

import (
	"strings"

	"github.com/anchore/syft/internal/presenter/packages"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

type syftDistribution struct {
	Name    string `json:"name"`    // Name of the Linux syftDistribution
	Version string `json:"version"` // Version of the Linux syftDistribution (major or major.minor version)
	IDLike  string `json:"idLike"`  // the ID_LIKE field found within the /etc/os-release file
}

type syftSource struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

// SyftDoc is the final package shape for a select elements from a syft JSON document.
type SyftDoc struct {
	Source    syftSource           `json:"source"`
	Artifacts []partialSyftPackage `json:"artifacts"`
	Distro    syftDistribution     `json:"distro"`
}

// partialSyftPackage is the final package shape for a select elements from a syft JSON package.
type partialSyftPackage struct {
	packageBasicMetadata
	packageCustomMetadata
}

// packageBasicMetadata contains non-ambiguous values (type-wise) from pkg.Package.
type packageBasicMetadata struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      pkg.Type          `json:"type"`
	Locations []source.Location `json:"locations"`
	Licenses  []string          `json:"licenses"`
	Language  pkg.Language      `json:"language"`
	CPEs      []string          `json:"cpes"`
	PURL      string            `json:"purl"`
}

// packageCustomMetadata contains ambiguous values (type-wise) from pkg.Package.
type packageCustomMetadata struct {
	MetadataType pkg.MetadataType `json:"metadataType"`
	Metadata     interface{}      `json:"metadata"`
}

func SBOMToSyftJSON(doc packages.CycloneDxDocument) *SyftDoc {
	var result *SyftDoc
	var artifacts = make([]partialSyftPackage, len(doc.Components))
	for _, a := range doc.Components {
		lcs := make([]string, 0)
		if a.Licenses != nil {
			for _, l := range *a.Licenses {
				lcs = append(lcs, l.Name)
			}
		}
		language := pkg.UnknownLanguage
		if strings.Contains(a.PackageURL, "golang") {
			language = pkg.Go
		}

		pkgBasicMeta := packageBasicMetadata{
			ID:       uuid.New().String(),
			Type:     getType(a.PackageURL),
			Version:  a.Version,
			Licenses: lcs,
			Name:     a.Name,
			CPEs:     []string{}, // CPE
			PURL:     a.PackageURL,
			Language: language,
		}
		meta, metaType := generateMetadata(a)
		artifact := partialSyftPackage{
			packageBasicMetadata: pkgBasicMeta,
			packageCustomMetadata: packageCustomMetadata{
				Metadata:     meta,
				MetadataType: metaType,
			},
		}
		// cpe.Generate(package)
		artifacts = append(artifacts, artifact)
	}
	result.Artifacts = artifacts
	result.Distro = syftDistribution{
		Name:    "",
		Version: "",
		IDLike:  "",
	}

	if doc.BomDescriptor != nil {
		source := convertBOMDescriptorToSource(*doc.BomDescriptor)
		result.Source = source
	}
	return result
}

func convertBOMDescriptorToSource(descriptor packages.CycloneDxBomDescriptor) syftSource {
	component := descriptor.Component
	var result syftSource
	if component.Name == "container" {
		var data map[string]string
		data["userInput"] = component.Name
		data["manifestDigest"] = component.Version
		result.Type = "image"
		result.Target = data
	} else if component.Name == "application" {
		var data map[string]string
		data["target"] = component.Name
		data["manifestDigest"] = component.Version
		result.Type = "directory"
		result.Target = data
	}
	return result
}

func getType(purl string) pkg.Type {
	if strings.Contains(purl, "python") {
		return pkg.PythonPkg
	}
	if strings.Contains(purl, "golang") {
		return pkg.GoModulePkg
	}

	if strings.Contains(purl, "deb") {
		return pkg.DebPkg
	}

	if strings.Contains(purl, "rpm") {
		return pkg.RpmPkg
	}
	return pkg.UnknownPkg
}

func getMetadataType(purl string) pkg.MetadataType {
	if strings.Contains(purl, "golang") {
		return pkg.GolangBinMetadataType
	}

	if strings.Contains(purl, "deb") {
		return pkg.DpkgMetadataType
	}

	if strings.Contains(purl, "rpm") {
		return pkg.RpmdbMetadataType
	}

	return pkg.RpmdbMetadataType
}

func getArchitecture(purl string) string {
	if strings.Contains(purl, "arch=amd64") {
		return "amd64"
	}

	return "all"
}

func generateMetadata(c packages.CycloneDxComponent) (interface{}, pkg.MetadataType) {
	metadataType := getMetadataType(c.PackageURL)
	var metadata interface{}

	switch metadataType {
	case pkg.ApkMetadataType:
		var payload pkg.ApkMetadata
		payload.Version = c.Version
		payload.Package = c.Name
		payload.Maintainer = c.Publisher
		payload.Description = c.Description
		metadata = payload
	case pkg.RpmdbMetadataType:
		var payload pkg.RpmdbMetadata
		payload.Version = c.Version
		payload.Name = c.Name
		payload.Arch = getArchitecture(c.PackageURL)
		payload.Vendor = c.Publisher
		payload.Version = c.PackageURL
		payload.Release = c.Supplier
		metadata = payload
	case pkg.DpkgMetadataType:
		var payload pkg.DpkgMetadata
		payload.Version = c.Version
		payload.Package = c.Name
		payload.Maintainer = c.Publisher
		payload.Architecture = getArchitecture(c.PackageURL)
		metadata = payload
	case pkg.JavaMetadataType:
		var payload pkg.JavaMetadata
		payload.VirtualPath = c.Name
		metadata = payload
	case pkg.RustCargoPackageMetadataType:
		var payload pkg.CargoPackageMetadata
		payload.Version = c.Version
		payload.Name = c.Name
		payload.Source = c.PackageURL
		metadata = payload
	case pkg.GemMetadataType:
		var payload pkg.GemMetadata
		payload.Version = c.Version
		payload.Name = c.Name
		payload.Authors = []string{c.Author}
		payload.Homepage = c.PackageURL
		metadata = payload
	case pkg.KbPackageMetadataType:
		var payload pkg.KbPackageMetadata
		payload.Kb = c.Name
		metadata = payload
	case pkg.PythonPackageMetadataType:
		var payload pkg.PythonPackageMetadata
		payload.Version = c.Version
		payload.Name = c.Name
		payload.Author = c.Publisher
		payload.Platform = c.Type
		metadata = payload
	case pkg.NpmPackageJSONMetadataType:
		var payload pkg.NpmPackageJSONMetadata
		payload.URL = c.PackageURL
		payload.Homepage = c.Publisher
		payload.Description = c.Description
		metadata = payload
	}
	return metadata, metadataType
}
