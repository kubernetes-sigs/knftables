/*
Copyright 2023 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nftables

import (
	"fmt"
	"os/exec"
	"testing"
)

func mkExecError(stderr string) error {
	return wrapError(&exec.ExitError{Stderr: []byte(stderr)})
}

func TestError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		isNotFound bool
		isExists   bool
	}{
		{
			name:       "generic doesn't exist",
			err:        mkExecError("Error: No such file or directory\ndelete element ip nosuchtable set {10.0.0.1}\n                  ^^^^^^^^^^^\n"),
			isNotFound: true,
			isExists:   false,
		},
		{
			name:       "doesn't exist with suggestion",
			err:        mkExecError("Error: No such file or directory; did you mean table ‘foo’ in family ip?\nblah blah blah\n"),
			isNotFound: true,
			isExists:   false,
		},
		{
			name:       "already exists",
			err:        mkExecError("Error: Could not process rule: File exists\ncreate table foo\n             ^^^"),
			isNotFound: false,
			isExists:   true,
		},
		{
			name:       "wrapped doesn't exist",
			err:        fmt.Errorf("oh my! %w", mkExecError("Error: No such file or directory")),
			isNotFound: true,
			isExists:   false,
		},
		{
			name:       "misc error",
			err:        mkExecError("Error: syntax error, unexpected string, expecting '{' or '$'"),
			isNotFound: false,
			isExists:   false,
		},
		{
			name:       "misleading misc error",
			err:        mkExecError("Error: syntax error, unexpected comment\nadd rule foo chain1 comment \"No such file or directory\" drop\n                    ^^^^^^^"),
			isNotFound: false,
			isExists:   false,
		},
		{
			name:       "not an ExecError, so not interpreted",
			err:        wrapError(fmt.Errorf("Error: No such file or directory\ndelete element ip nosuchtable set {10.0.0.1}\n                  ^^^^^^^^^^^\n")),
			isNotFound: false,
			isExists:   false,
		},
		{
			name:       "fake not found",
			err:        notFoundError("not found"),
			isNotFound: true,
			isExists:   false,
		},
		{
			name:       "fake exists",
			err:        existsError("already exists"),
			isNotFound: false,
			isExists:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if IsNotFound(tc.err) != tc.isNotFound {
				t.Errorf("expected IsNotFound %v, got %v", tc.isNotFound, IsNotFound(tc.err))
			}
			if IsAlreadyExists(tc.err) != tc.isExists {
				t.Errorf("expected IsAlreadyExists %v, got %v", tc.isExists, IsAlreadyExists(tc.err))
			}
		})
	}
}
