/*
Defines a Presenter interface for displaying catalog results to an io.Writer as well as a helper utility to obtain
a specific Presenter implementation given user configuration.
*/
package packages

import (
	"github.com/anchore/syft/internal/formats"
	"github.com/anchore/syft/internal/presenter/packages"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/presenter"
	"github.com/anchore/syft/syft/sbom"
)

// Presenter returns a presenter for images or directories
func Presenter(option format.Option, s sbom.SBOM) presenter.Presenter {
	switch option {
	case format.SPDXTagValueOption:
		return packages.NewSPDXTagValuePresenter(s.Artifacts.PackageCatalog, s.Source)
	default:
		// TODO: the final state is that all other cases would be replaced by formats.ByOption (wed remove this function entirely)
		f := formats.ByOption(option)
		if f == nil {
			return nil
		}
		return f.Presenter(s)
	}
}
