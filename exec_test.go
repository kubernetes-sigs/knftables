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

package knftables

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

type execTestCase struct {
	name        string
	command     []string
	stdin       string
	expectedOut string
	expectedErr string
}

var execTestCases = []execTestCase{
	{
		name:        "/bin/true",
		command:     []string{"/bin/true"},
		expectedOut: "",
	},
	{
		name:        "/bin/false",
		command:     []string{"/bin/false"},
		expectedOut: "",
		expectedErr: "exit status 1",
	},
	{
		name:        "echo",
		command:     []string{"echo", "one", "two", "three"},
		expectedOut: "one two three\n",
	},
	{
		name:        "with stdin",
		command:     []string{"cat"},
		stdin:       "one\ntwo\nthree\n",
		expectedOut: "one\ntwo\nthree\n",
	},
	{
		name:        "missing command",
		command:     []string{"/does/not/exist/command"},
		expectedOut: "",
		expectedErr: "no such file or directory",
	},
	{
		name:        "fail",
		command:     []string{"cat", "."},
		expectedOut: "",
		expectedErr: "Is a directory",
	},
}

func TestRealExec(t *testing.T) {
	for _, tc := range execTestCases {
		t.Run(tc.name, func(t *testing.T) {
			execer := &realExec{}
			cmd := exec.Command(tc.command[0], tc.command[1:]...)
			if tc.stdin != "" {
				cmd.Stdin = bytes.NewBufferString(tc.stdin)
			}
			out, err := execer.Run(cmd)
			if out != tc.expectedOut {
				t.Errorf("expected output %q, got %q", tc.expectedOut, out)
			}
			if err != nil {
				if tc.expectedErr == "" {
					t.Errorf("expected no error, got %v", err)
				} else if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Errorf("expected error containing %q, got %v", tc.expectedErr, err)
				}
			} else if tc.expectedErr != "" {
				t.Errorf("expected error containing %q, got no error", tc.expectedErr)
			}
		})
	}
}

func TestFakeExec(t *testing.T) {
	for _, tc := range execTestCases {
		t.Run(tc.name, func(t *testing.T) {
			execer := newFakeExec(t)
			execer.missingBinaries["/does/not/exist/command"] = true
			execer.expected = []expectedCmd{{
				args:   tc.command,
				stdin:  tc.stdin,
				stdout: tc.expectedOut,
			}}
			if tc.expectedErr != "" {
				execer.expected[0].err = fmt.Errorf(tc.expectedErr)
			}

			cmd := exec.Command(tc.command[0], tc.command[1:]...)
			if tc.stdin != "" {
				cmd.Stdin = bytes.NewBufferString(tc.stdin)
			}
			out, err := execer.Run(cmd)
			if out != tc.expectedOut {
				t.Errorf("expected output %q, got %q", tc.expectedOut, out)
			}
			if err != nil {
				if tc.expectedErr == "" {
					t.Errorf("expected no error, got %v", err)
				} else if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Errorf("expected error containing %q, got %v", tc.expectedErr, err)
				}
			} else if tc.expectedErr != "" {
				t.Errorf("expected error containing %q, got no error", tc.expectedErr)
			}
		})
	}
}
