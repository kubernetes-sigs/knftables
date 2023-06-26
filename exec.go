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
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// execer is a mockable wrapper around os/exec.
type execer interface {
	// Run wraps exec.Cmd.Run
	Run(cmd *exec.Cmd) error

	// CombinedOutput wraps exec.Cmd.CombinedOutput
	CombinedOutput(cmd *exec.Cmd) ([]byte, error)
}

// realExec implements execer by actually using os/exec
type realExec struct {}

func (_ realExec) Run(cmd *exec.Cmd) error {
	return cmd.Run()
}

func (_ realExec) CombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	return cmd.CombinedOutput()
}

// fakeExec is a mockable implementation of execer for unit tests
type fakeExec struct {
	t *testing.T 

	expected []expectedCmd
	matched  int
}

func newFakeExec(t *testing.T) *fakeExec {
	return &fakeExec{t: t}
}

// expectedCmd details one expected fakeExec Cmd
type expectedCmd struct {
	args   []string
	stdin  string
	stdout string
	stderr string
	err    error
}

func (fe *fakeExec) check(cmd *exec.Cmd) (*expectedCmd, error) {
	if fe.t.Failed() {
		return nil, fmt.Errorf("unit test failed")
	}

	if len(fe.expected) == fe.matched {
		fe.t.Errorf("ran out of commands before executing %s %s", cmd.Path, strings.Join(cmd.Args, " "))
		return nil, fmt.Errorf("unit test failed")
	}
	expected := &fe.expected[fe.matched]
	fe.matched++

	if !reflect.DeepEqual(expected.args, cmd.Args) {
		fe.t.Errorf("incorrect arguments: expected %v, got %v", expected.args, cmd.Args)
		return nil, fmt.Errorf("unit test failed")
	}

	var stdin string
	if cmd.Stdin != nil {
		inBytes, _ := io.ReadAll(cmd.Stdin)
		stdin = string(inBytes)
	}
	if expected.stdin != stdin {
		fe.t.Errorf("incorrect stdin: expected %q, got %q", expected.stdin, stdin)
		return nil, fmt.Errorf("unit test failed")
	}

	return expected, nil
}

func (fe *fakeExec) Run(cmd *exec.Cmd) error {
	expected, err := fe.check(cmd)
	if err != nil {
		return err
	}

	if cmd.Stdout != nil {
		_, _ = cmd.Stdout.Write([]byte(expected.stdout))
	}
	if cmd.Stderr != nil {
		_, _ = cmd.Stderr.Write([]byte(expected.stderr))
	}
	return expected.err
}

func (fe *fakeExec) CombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	expected, err := fe.check(cmd)
	if err != nil {
		return nil, err
	}

	return []byte(expected.stdout+expected.stderr), expected.err
}
