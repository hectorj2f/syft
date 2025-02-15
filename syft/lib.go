/*
A "one-stop-shop" for helper utilities for all major functionality provided by child packages of the syft library.

Here is what the main execution path for syft does:

	1. Parse a user image string to get a stereoscope image.Source object
	2. Invoke all catalogers to catalog the image, adding discovered packages to a single catalog object
	3. Invoke a single presenter to show the contents of the catalog

A Source object encapsulates the image object to be cataloged and the user options (catalog all layers vs. squashed layer),
providing a way to inspect paths and file content within the image. The Source object, not the image object, is used
throughout the main execution path. This abstraction allows for decoupling of what is cataloged (a docker image, an OCI
image, a filesystem, etc) and how it is cataloged (the individual catalogers).

Similar to the cataloging process, Linux distribution identification is also performed based on what is discovered within the image.
*/
package syft

import (
	"fmt"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/logger"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
)

// CatalogPackages takes an inventory of packages from the given image from a particular perspective
// (e.g. squashed source, all-layers source). Returns the discovered  set of packages, the identified Linux
// distribution, and the source object used to wrap the data source.
func CatalogPackages(src *source.Source, scope source.Scope) (*pkg.Catalog, *distro.Distro, error) {
	resolver, err := src.FileResolver(scope)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to determine resolver while cataloging packages: %w", err)
	}

	// find the distro
	theDistro := distro.Identify(resolver)
	if theDistro != nil {
		log.Infof("identified distro: %s", theDistro.String())
	} else {
		log.Info("could not identify distro")
	}

	// conditionally use the correct set of loggers based on the input type (container image or directory)
	var catalogers []cataloger.Cataloger
	switch src.Metadata.Scheme {
	case source.ImageScheme:
		log.Info("cataloging image")
		catalogers = cataloger.ImageCatalogers()
	case source.DirectoryScheme:
		log.Info("cataloging directory")
		catalogers = cataloger.DirectoryCatalogers()
	default:
		return nil, nil, fmt.Errorf("unable to determine cataloger set from scheme=%+v", src.Metadata.Scheme)
	}

	catalog, err := cataloger.Catalog(resolver, theDistro, catalogers...)
	if err != nil {
		return nil, nil, err
	}

	return catalog, theDistro, nil
}

// SetLogger sets the logger object used for all syft logging calls.
func SetLogger(logger logger.Logger) {
	log.Log = logger
}

// SetBus sets the event bus for all syft library bus publish events onto (in-library subscriptions are not allowed).
func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
