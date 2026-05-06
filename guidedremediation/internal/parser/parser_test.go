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

package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindWorkspaceRoot(t *testing.T) {
	// Create a temporary directory structure
	tmpDir := t.TempDir()

	// Create a fake workspace root
	workspaceRoot := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(workspaceRoot, 0755); err != nil {
		t.Fatal(err)
	}

	// Touch a WORKSPACE file to simulate a repository
	if err := os.WriteFile(filepath.Join(workspaceRoot, "WORKSPACE"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a nested file path
	nestedFile := filepath.Join(workspaceRoot, "pkg", "core", "pom.xml")
	if err := os.MkdirAll(filepath.Dir(nestedFile), 0755); err != nil {
		t.Fatal(err)
	}

	// Test 1: File within the workspace should resolve the workspace root
	root := findWorkspaceRoot(nestedFile)
	if root != workspaceRoot {
		t.Errorf("Expected root %q, got %q", workspaceRoot, root)
	}

	// Test 2: File outside any workspace should fallback to working directory or file's directory
	outsideDir := filepath.Join(tmpDir, "outside")
	outsideFile := filepath.Join(outsideDir, "test.txt")
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatal(err)
	}

	rootOutside := findWorkspaceRoot(outsideFile)
	wd, _ := os.Getwd()
	expectedFallback := wd
	// if outsideFile is not inside wd, it falls back to filepath.Dir(outsideFile)
	if !strings.HasPrefix(outsideFile, wd) {
		expectedFallback = outsideDir
	}
	if rootOutside != expectedFallback {
		t.Errorf("Expected fallback root %q, got %q", expectedFallback, rootOutside)
	}
}
