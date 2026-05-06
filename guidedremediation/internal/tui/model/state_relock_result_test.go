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

package model

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/guidedremediation/internal/parser"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/options"
)

func TestStateRelockResult_Write_Npm_IgnoreScripts(t *testing.T) {
	tmpDir := t.TempDir()

	fakeNpm := filepath.Join(tmpDir, "npm")
	script := `#!/bin/bash
echo "$@" > "` + tmpDir + `/npm_args.txt"
`
	if err := os.WriteFile(fakeNpm, []byte(script), 0755); err != nil {
		t.Fatalf("Failed to create fake npm: %v", err)
	}

	oldPath := os.Getenv("PATH")
	defer os.Setenv("PATH", oldPath)
	os.Setenv("PATH", tmpDir+string(os.PathListSeparator)+oldPath)

	manifestPath := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(manifestPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	manifestRW, _ := npm.GetReadWriter()
	manif, _ := parser.ParseManifest(manifestPath, manifestRW)

	m := Model{
		options: options.FixVulnsOptions{
			Manifest: manifestPath,
			Lockfile: filepath.Join(tmpDir, "package-lock.json"),
		},
		manifestRW: manifestRW,
		relockBaseManifest: &remediation.ResolvedManifest{
			Manifest: manif,
		},
	}

	st := stateRelockResult{
		currRes: &remediation.ResolvedManifest{
			Manifest: manif,
		},
	}

	msg := st.write(m)

	msgVal := reflect.ValueOf(msg)
	addrMsgVal := reflect.New(msgVal.Type())
	addrMsgVal.Elem().Set(msgVal)

	cmdField := addrMsgVal.Elem().FieldByName("cmd")

	// Bypass unexported field restriction
	execCmdPtr := reflect.NewAt(cmdField.Type(), unsafe.Pointer(cmdField.UnsafeAddr())).Elem()

	execCmdIfc := execCmdPtr.Interface()

	// execCmdIfc is tea.ExecCommand. We can cast it to an interface with Run()
	type runner interface {
		Run() error
	}
	r, ok := execCmdIfc.(runner)
	if !ok {
		t.Fatalf("Could not cast to runner")
	}

	_ = r.Run()

	argsData, err := os.ReadFile(filepath.Join(tmpDir, "npm_args.txt"))
	if err != nil {
		t.Fatalf("Failed to read npm_args.txt: %v", err)
	}
	args := string(argsData)
	if !strings.Contains(args, "--ignore-scripts") {
		t.Errorf("Expected npm install to have --ignore-scripts, but got: %s", args)
	}
}
