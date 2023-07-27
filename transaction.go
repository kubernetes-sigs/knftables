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
	operations []operation
	err        error
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

// NewTransaction creates a new transaction.
func NewTransaction() *Transaction {
	return &Transaction{}
}

// asCommandBuf returns the transaction as an io.Reader that outputs a series of nft commands
func (tx *Transaction) asCommandBuf(family Family, table string) (io.Reader, error) {
	if tx.err != nil {
		return nil, tx.err
	}

	buf := &bytes.Buffer{}
	for _, op := range tx.operations {
		op.obj.writeOperation(op.verb, family, table, buf)
	}
	return buf, nil
}

func (tx *Transaction) operation(verb verb, obj Object) {
	if tx.err != nil {
		return
	}
	if tx.err = obj.validate(verb); tx.err != nil {
		return
	}

	tx.operations = append(tx.operations, operation{verb: verb, obj: obj})
}

// Add adds an "nft add" operation to tx, ensuring that obj exists by creating it if it
// did not already exist. (If obj is a Rule, it will be appended to the end of its chain,
// or else added after the Rule indicated by this rule's Index or Handle.) The Add() call
// always succeeds, but if obj is invalid, or inconsistent with the existing nftables
// state, then an error will be returned when the transaction is Run.
func (tx *Transaction) Add(obj Object) {
	tx.operation(addVerb, obj)
}

// Create adds an "nft create" operation to tx, creating obj, which must not already
// exist. The Create() call always succeeds, but if obj is invalid, already exists, or is
// inconsistent with the existing nftables state, then an error will be returned when the
// transaction is Run.
func (tx *Transaction) Create(obj Object) {
	tx.operation(createVerb, obj)
}

// Flush adds an "nft flush" operation to tx, clearing the contents of obj. The Flush()
// call always succeeds, but if obj does not exist (or does not support flushing) then an
// error will be returned when the transaction is Run.
func (tx *Transaction) Flush(obj Object) {
	tx.operation(flushVerb, obj)
}

// Delete adds an "nft delete" operation to tx, deleting obj. The Delete() call always
// succeeds, but if obj does not exist or cannot be deleted based on the information
// provided (eg, Handle is required but not set) then an error will be returned when the
// transaction is Run.
func (tx *Transaction) Delete(obj Object) {
	tx.operation(deleteVerb, obj)
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
