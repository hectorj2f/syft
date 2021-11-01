package cmd

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"

	"github.com/mitchellh/go-homedir"

	"github.com/anchore/syft/internal/presenter/packages"
	"github.com/anchore/syft/syft/convert"
	"github.com/spf13/cobra"
)

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "convert SBOM to Syft JSON",
	Run:   convertSBOMToSyftJSON,
}

// ---- Syft json to grype objects

// fetch Artifacts: ID, Name, Version and Type, PURL
// 		get the CPEs per artifact
// 		Create packages with artifacts and CPEs
// Looks for the distro name
// Gets "source" document Type and based on whether is a directory or image
// get Target, DirectoScheme OR imageSchem and Target.ImageMEtadata

func init() {
	// convertCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "format to show version information (available=[text, json])")
	rootCmd.AddCommand(convertCmd)
}

func openSbom(path string) (*os.File, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %w", err)
	}

	sbom, err := os.Open(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %s %w", expandedPath, err)
	}

	return sbom, nil
}

func convertSBOMToSyftJSON(_ *cobra.Command, _ []string) {
	reader, err := openSbom(os.Args[2])
	if err != nil {
		fmt.Printf("failed to open sbom file: %+v\n", err)
		os.Exit(1)
	}
	var doc packages.CycloneDxDocument
	decoder := xml.NewDecoder(reader)
	if err := decoder.Decode(&doc); err != nil {
		fmt.Printf("failed to decode sbom file: %+v\n", err)
		os.Exit(1)
	}

	result := convert.SBOMToSyftJSON(doc)

	err = writeSyftDocument(*result, os.Stdout)
	if err != nil {
		fmt.Printf("failed to write Syft sbom file: %+v\n", err)
		os.Exit(1)
	}
}

// writeSyftDocument creates a file of Syft using a CycloneDX-based reporting
func writeSyftDocument(bom convert.SyftDoc, output io.Writer) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")

	_, err := output.Write([]byte(xml.Header))
	if err != nil {
		return err
	}

	err = encoder.Encode(bom)

	if err != nil {
		return err
	}

	return err
}
