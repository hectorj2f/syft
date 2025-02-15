package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestFingerprint(t *testing.T) {
	originalPkg := Package{
		ID:      "π",
		Name:    "pi",
		Version: "3.14",
		FoundBy: "Archimedes",
		Locations: []source.Location{
			{
				RealPath:     "39.0742° N, 21.8243° E",
				VirtualPath:  "/Ancient-Greece",
				FileSystemID: "Earth",
			},
		},
		Licenses: []string{
			"cc0-1.0",
			"MIT",
		},
		Language: "math",
		Type:     PythonPkg,
		CPEs: []CPE{
			must(NewCPE(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`)),
		},
		PURL:         "pkg:pypi/pi@3.14",
		MetadataType: PythonPackageMetadataType,
		Metadata: PythonPackageMetadata{
			Name:                 "pi",
			Version:              "3.14",
			License:              "cc0-1.0",
			Author:               "Archimedes",
			AuthorEmail:          "Archimedes@circles.io",
			Platform:             "universe",
			SitePackagesRootPath: "Pi",
		},
	}

	// this is a set of differential tests, ensuring that select mutations are reflected in the fingerprint (or not)
	tests := []struct {
		name            string
		transform       func(pkg Package) Package
		expectIdentical bool
	}{
		{
			name: "go case (no transform)",
			transform: func(pkg Package) Package {
				// do nothing!
				return pkg
			},
			expectIdentical: true,
		},
		{
			name: "same metadata is ignored",
			transform: func(pkg Package) Package {
				// note: this is the same as the original values, just a new allocation
				pkg.Metadata = PythonPackageMetadata{
					Name:                 "pi",
					Version:              "3.14",
					License:              "cc0-1.0",
					Author:               "Archimedes",
					AuthorEmail:          "Archimedes@circles.io",
					Platform:             "universe",
					SitePackagesRootPath: "Pi",
				}
				return pkg
			},
			expectIdentical: true,
		},
		{
			name: "licenses order is ignored",
			transform: func(pkg Package) Package {
				// note: same as the original package, only a different order
				pkg.Licenses = []string{
					"MIT",
					"cc0-1.0",
				}
				return pkg
			},
			expectIdentical: true,
		},
		{
			name: "name is reflected",
			transform: func(pkg Package) Package {
				pkg.Name = "new!"
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "version is reflected",
			transform: func(pkg Package) Package {
				pkg.Version = "new!"
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "licenses is reflected",
			transform: func(pkg Package) Package {
				pkg.Licenses = []string{"new!"}
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "type is reflected",
			transform: func(pkg Package) Package {
				pkg.Type = RustPkg
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "metadata type is reflected",
			transform: func(pkg Package) Package {
				pkg.MetadataType = RustCargoPackageMetadataType
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "CPEs is reflected",
			transform: func(pkg Package) Package {
				pkg.CPEs = []CPE{}
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "pURL is reflected",
			transform: func(pkg Package) Package {
				pkg.PURL = "new!"
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "language is reflected",
			transform: func(pkg Package) Package {
				pkg.Language = Rust
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "foundBy is reflected",
			transform: func(pkg Package) Package {
				pkg.FoundBy = "new!"
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "metadata mutation is reflected",
			transform: func(pkg Package) Package {
				metadata := pkg.Metadata.(PythonPackageMetadata)
				metadata.Name = "new!"
				pkg.Metadata = metadata
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "new metadata is reflected",
			transform: func(pkg Package) Package {
				pkg.Metadata = PythonPackageMetadata{
					Name: "new!",
				}
				return pkg
			},
			expectIdentical: false,
		},
		{
			name: "nil metadata is reflected",
			transform: func(pkg Package) Package {
				pkg.Metadata = nil
				return pkg
			},
			expectIdentical: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transformedPkg := test.transform(originalPkg)
			originalFingerprint, err := originalPkg.Fingerprint()
			assert.NoError(t, err, "expected no error on package fingerprint")
			transformedFingerprint, err := transformedPkg.Fingerprint()
			assert.NoError(t, err, "expected no error on package fingerprint")

			if test.expectIdentical {
				assert.Equal(t, originalFingerprint, transformedFingerprint)
			} else {
				assert.NotEqual(t, originalFingerprint, transformedFingerprint)
			}

		})
	}
}
