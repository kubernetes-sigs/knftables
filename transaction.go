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
	"bytes"
	"fmt"
	"io"
)

// Transaction represents an nftables transaction
type Transaction struct {
	defines []define

	operations []operation
	err        error
}

// define stores an nftables define. (We have to use `[]define` rather than
// `map[string]string` because order is important.)
type define struct {
	name  string
	value string
}

// operation contains a single nftables operation (eg "add table", "flush chain")
type operation struct {
	verb verb
	obj  Object
}

// verb is used internally to represent the different "nft" verbs
type verb string

const (
	addVerb     verb = "add"
	createVerb  verb = "create"
	insertVerb  verb = "insert"
	replaceVerb verb = "replace"
	deleteVerb  verb = "delete"
	flushVerb   verb = "flush"
)

// NewTransaction creates a new transaction acting on the given family and table.
func NewTransaction() *Transaction {
	return &Transaction{}
}

// Define adds a define ("nft -D") to tx, which can then be referenced as `$name` in the
// transaction body (e.g., rules, elements, etc; any string-valued Object field).
func (tx *Transaction) Define(name, value string) {
	tx.defines = append(tx.defines, define{name, value})
}

// asCommandBuf returns the transaction as an io.Reader that outputs a series of nft commands
func (tx *Transaction) asCommandBuf(family Family, table string) (io.Reader, error) {
	if tx.err != nil {
		return nil, tx.err
	}

	buf := &bytes.Buffer{}
	for _, def := range tx.defines {
		_, err := fmt.Fprintf(buf, "define %s = %s\n", def.name, def.value)
		if err != nil {
			return nil, err
		}
	}
	for _, op := range tx.operations {
		op.obj.writeOperation(op.verb, family, table, buf)
	}
	return buf, nil
}

// Add adds an "nft add" operation to tx, ensuring that obj exists by creating it if it
// did not already exist. The Add() call always succeeds, but if obj is invalid, or
// inconsistent with the existing nftables state, then an error will be returned when the
// transaction is Run.
func (tx *Transaction) Add(obj Object) {
	if tx.err != nil {
		return
	}
	if tx.err = obj.validate(addVerb); tx.err != nil {
		return
	}

	tx.operations = append(tx.operations, operation{verb: addVerb, obj: obj})
}

// Flush adds an "nft flush" operation to tx, clearing the contents of obj. The Flush()
// call always succeeds, but if obj does not exist (or does not support flushing) then an
// error will be returned when the transaction is Run.
func (tx *Transaction) Flush(obj Object) {
	if tx.err != nil {
		return
	}
	if tx.err = obj.validate(flushVerb); tx.err != nil {
		return
	}

	tx.operations = append(tx.operations, operation{verb: flushVerb, obj: obj})
}

// Delete adds an "nft delete" operation to tx, deleting obj. The Delete() call always
// succeeds, but if obj does not exist or cannot be deleted based on the information
// provided (eg, Handle is required but not set) then an error will be returned when the
// transaction is Run.
func (tx *Transaction) Delete(obj Object) {
	if tx.err != nil {
		return
	}
	if tx.err = obj.validate(deleteVerb); tx.err != nil {
		return
	}

	tx.operations = append(tx.operations, operation{verb: deleteVerb, obj: obj})
}

// AddRule is a helper for adding Rule objects. It takes a series of string and []string
// arguments and concatenates them together into a single rule. As with "nft add rule",
// you may include a comment (which must be quoted) as the last clause of the rule.
func (tx *Transaction) AddRule(chain string, args ...interface{}) {
	if tx.err != nil {
		return
	}

	buf := &bytes.Buffer{}
	for _, arg := range args {
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		switch x := arg.(type) {
		case string:
			buf.WriteString(x)
		case []string:
			for j, s := range x {
				if j > 0 {
					buf.WriteByte(' ')
				}
				buf.WriteString(s)
			}
		default:
			panic(fmt.Sprintf("unknown argument type: %T", x))
		}
	}

	rule, comment := splitComment(buf.String())
	tx.Add(&Rule{
		Chain:   chain,
		Rule:    rule,
		Comment: comment,
	})
}
