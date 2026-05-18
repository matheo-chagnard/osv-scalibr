// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pdmlock extracts pdm.lock files.
package pdmlock

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pdmlock"
)

type pdmLockPackage struct {
	Name     string   `toml:"name"`
	Version  string   `toml:"version"`
	Groups   []string `toml:"groups"`
	Revision string   `toml:"revision"`
}

type pdmLockFile struct {
	Version  string           `toml:"lock-version"`
	Packages []pdmLockPackage `toml:"package"`
}

// Extractor extracts python packages from pdm.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches PDM lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pdm.lock"
}

// Extract extracts packages from pdm.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read file: %w", err)
	}

	var parsedLockFile *pdmLockFile
	if err := toml.Unmarshal(content, &parsedLockFile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packageNames := make([]string, 0, len(parsedLockFile.Packages))
	for _, p := range parsedLockFile.Packages {
		packageNames = append(packageNames, p.Name)
	}
	lineNums := findPackageLineNumbers(content, packageNames)

	packages := make([]*extractor.Package, 0, len(parsedLockFile.Packages))

	for i, parsedPKG := range parsedLockFile.Packages {
		pkg := &extractor.Package{
			Name:     parsedPKG.Name,
			Version:  parsedPKG.Version,
			PURLType: purl.TypePyPi,
			Location: extractor.LocationFromPathAndLine(input.Path, lineNums[i]),
		}

		depGroups := parseGroupsToDepGroups(parsedPKG.Groups)

		pkg.Metadata = &osv.DepGroupMetadata{
			DepGroupVals: depGroups,
		}

		if parsedPKG.Revision != "" {
			pkg.SourceCode = &extractor.SourceCodeIdentifier{
				Commit: parsedPKG.Revision,
			}
		}

		packages = append(packages, pkg)
	}

	return inventory.Inventory{Packages: packages}, nil
}

var nameRegex = regexp.MustCompile(`^name\s*=\s*["']([^"']+)["']`)

func findPackageLineNumbers(content []byte, packageNames []string) []int {
	lineNums := make([]int, len(packageNames))
	scanner := bufio.NewScanner(bytes.NewReader(content))
	currentLine := 0
	pkgIdx := 0
	inPackageBlock := false

	for scanner.Scan() {
		currentLine++
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			inPackageBlock = true
			continue
		}

		if inPackageBlock && strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[package]]") {
			inPackageBlock = false
		}

		if inPackageBlock && pkgIdx < len(packageNames) {
			matches := nameRegex.FindStringSubmatch(line)
			if len(matches) > 1 && matches[1] == packageNames[pkgIdx] {
				lineNums[pkgIdx] = currentLine
				pkgIdx++
				inPackageBlock = false
			}
		}
	}
	return lineNums
}

// parseGroupsToDepGroups converts pdm lockfile groups to the standard DepGroups
func parseGroupsToDepGroups(groups []string) []string {
	depGroups := []string{}

	var optional = true
	for _, gr := range groups {
		// depGroups can either be:
		// [], [dev], [optional]
		// All packages not in the default group (or the dev group)
		// are optional.
		if gr == "dev" {
			depGroups = append(depGroups, "dev")
			optional = false
		} else if gr == "default" {
			optional = false
		}
	}
	if optional {
		depGroups = append(depGroups, "optional")
	}

	return depGroups
}

var _ filesystem.Extractor = Extractor{}
