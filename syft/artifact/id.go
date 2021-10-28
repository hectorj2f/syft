package artifact

import "github.com/google/uuid"

// ID represents a unique value for each package added to a package catalog.
type ID string

// TODO: this will be replaced with fingerprinting
func NewID() ID {
	return ID(uuid.New().String())
}
