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
	"context"
	"fmt"
	"sort"
	"strings"
)

// Fake is a fake implementation of Interface
type Fake struct {
	// Tables contains the defined tables, keyed by family and name
	Tables map[Family]map[string]*FakeTable
}

// FakeTable wraps Table for the Fake implementation
type FakeTable struct {
	Table

	Chains map[string]*FakeChain
	Sets   map[string]*FakeSet
	Maps   map[string]*FakeMap
}

// FakeChain wraps Chain for the Fake implementation
type FakeChain struct {
	Chain

	Rules []*Rule
}

// FakeSet wraps Set for the Fake implementation
type FakeSet struct {
	Set

	Elements []*Element
}

// FakeMap wraps Set for the Fake implementation
type FakeMap struct {
	Map

	Elements []*Element
}

func NewFake() *Fake {
	return &Fake{
		Tables: make(map[Family]map[string]*FakeTable),
	}
}

var _ Interface = &Fake{}

// Present is part of Interface.
func (fake *Fake) Present() error {
	return nil
}

// List is part of Interface.
func (fake *Fake) List(ctx context.Context, family Family, tableName, objectType string) ([]string, error) {
	table := fake.Tables[family][tableName]
	if table == nil {
		return nil, fmt.Errorf("no such table %q", tableName)
	}

	var result []string

	switch objectType {
	case "chain", "chains":
		for name := range table.Chains {
			result = append(result, name)
		}
	case "set", "sets":
		for name := range table.Sets {
			result = append(result, name)
		}
	case "map", "maps":
		for name := range table.Maps {
			result = append(result, name)
		}

	default:
		return nil, fmt.Errorf("unsupported object type %q", objectType)
	}

	return result, nil
}

func substituteDefines(val string, tx *Transaction) string {
	for _, def := range tx.defines {
		val = strings.ReplaceAll(val, "$"+def.name, def.value)
	}
	return val
}

// Run is part of Interface
func (fake *Fake) Run(ctx context.Context, tx *Transaction) error {
	if tx.err != nil {
		return tx.err
	}

	// FIXME: not actually transactional!

	for _, op := range tx.operations {
		tables := fake.Tables[tx.family]
		if tables == nil {
			fake.Tables[tx.family] = make(map[string]*FakeTable)
		}
		existingTable := fake.Tables[tx.family][tx.table]
		if existingTable == nil {
			if _, ok := op.obj.(*Table); !ok || op.verb != addVerb {
				return fmt.Errorf("no such table \"%s %s\"", tx.family, tx.table)
			}
		}

		switch obj := op.obj.(type) {
		case *Table:
			switch op.verb {
			case flushVerb:
				delete(fake.Tables[tx.family], tx.table)
				existingTable = nil
				fallthrough
			case addVerb:
				if existingTable == nil {
					fake.Tables[tx.family][tx.table] = &FakeTable{
						Table:  *obj,
						Chains: make(map[string]*FakeChain),
						Sets:   make(map[string]*FakeSet),
						Maps:   make(map[string]*FakeMap),
					}
				}
			case deleteVerb:
				delete(fake.Tables[tx.family], tx.table)
			default:
				return fmt.Errorf("unhandled operation %q", op.verb)
			}
		case *Chain:
			existingChain := existingTable.Chains[obj.Name]
			if existingChain == nil && op.verb != addVerb {
				return fmt.Errorf("no such chain %q", obj.Name)
			}
			switch op.verb {
			case addVerb:
				if existingChain != nil {
					continue
				}
				existingTable.Chains[obj.Name] = &FakeChain{
					Chain: *obj,
				}
			case flushVerb:
				existingChain.Rules = nil
			case deleteVerb:
				// FIXME delete-by-handle
				delete(existingTable.Chains, obj.Name)
			default:
				return fmt.Errorf("unhandled operation %q", op.verb)
			}
		case *Rule:
			existingChain := existingTable.Chains[obj.Chain]
			if existingChain == nil {
				return fmt.Errorf("no such chain %q", obj.Chain)
			}
			switch op.verb {
			case addVerb:
				rule := *obj
				rule.Rule = substituteDefines(rule.Rule, tx)
				existingChain.Rules = append(existingChain.Rules, &rule)
			case deleteVerb:
				// FIXME
				return fmt.Errorf("unimplemented operation %q", op.verb)
			default:
				return fmt.Errorf("unhandled operation %q", op.verb)
			}
		case *Set:
			existingSet := existingTable.Sets[obj.Name]
			if existingSet == nil && op.verb != addVerb {
				return fmt.Errorf("no such set %q", obj.Name)
			}
			switch op.verb {
			case addVerb:
				if existingSet != nil {
					continue
				}
				set := *obj
				set.Type = substituteDefines(set.Type, tx)
				set.TypeOf = substituteDefines(set.TypeOf, tx)
				existingTable.Sets[obj.Name] = &FakeSet{
					Set: set,
				}
			case flushVerb:
				existingSet.Elements = nil
			case deleteVerb:
				// FIXME delete-by-handle
				delete(existingTable.Sets, obj.Name)
			default:
				return fmt.Errorf("unhandled operation %q", op.verb)
			}
		case *Map:
			existingMap := existingTable.Maps[obj.Name]
			if existingMap == nil && op.verb != addVerb {
				return fmt.Errorf("no such map %q", obj.Name)
			}
			switch op.verb {
			case addVerb:
				if existingMap != nil {
					continue
				}
				mapObj := *obj
				mapObj.Type = substituteDefines(mapObj.Type, tx)
				mapObj.TypeOf = substituteDefines(mapObj.TypeOf, tx)
				existingTable.Maps[obj.Name] = &FakeMap{
					Map: mapObj,
				}
			case flushVerb:
				existingMap.Elements = nil
			case deleteVerb:
				// FIXME delete-by-handle
				delete(existingTable.Maps, obj.Name)
			default:
				return fmt.Errorf("unhandled operation %q", op.verb)
			}
		case *Element:
			if len(obj.Value) == 0 {
				existingSet := existingTable.Sets[obj.Name]
				if existingSet == nil {
					return fmt.Errorf("no such set %q", obj.Name)
				}
				switch op.verb {
				case addVerb:
					element := *obj
					element.Key = substituteDefines(element.Key, tx)
					existingSet.Elements = append(existingSet.Elements, &element)
				case deleteVerb:
					// FIXME
					return fmt.Errorf("unimplemented operation %q", op.verb)
				default:
					return fmt.Errorf("unhandled operation %q", op.verb)
				}
			} else {
				existingMap := existingTable.Maps[obj.Name]
				if existingMap == nil {
					return fmt.Errorf("no such map %q", obj.Name)
				}
				switch op.verb {
				case addVerb:
					element := *obj
					element.Key = substituteDefines(element.Key, tx)
					element.Value = substituteDefines(element.Value, tx)
					existingMap.Elements = append(existingMap.Elements, &element)
				case deleteVerb:
					// FIXME
					return fmt.Errorf("unimplemented operation %q", op.verb)
				default:
					return fmt.Errorf("unhandled operation %q", op.verb)
				}
			}
		default:
			return fmt.Errorf("unhandled object type %T", op.obj)
		}
	}

	return nil
}

// Dump dumps the current contents of fake, in a way that looks like an nft transaction,
// but not actually guaranteed to be usable as such. (e.g., chains may be referenced
// before they are created, etc)
func (fake *Fake) Dump() string {
	buf := &strings.Builder{}

	for _, family := range sortKeys(fake.Tables) {
		tables := fake.Tables[Family(family)]
		for _, tname := range sortKeys(tables) {
			table := tables[tname]
			table.writeOperation(addVerb, family, tname, buf)

			for _, cname := range sortKeys(table.Chains) {
				ch := table.Chains[cname]
				ch.writeOperation(addVerb, family, tname, buf)

				for _, rule := range ch.Rules {
					rule.writeOperation(addVerb, family, tname, buf)
				}
			}

			for _, sname := range sortKeys(table.Sets) {
				s := table.Sets[sname]
				s.writeOperation(addVerb, family, tname, buf)

				for _, element := range s.Elements {
					element.writeOperation(addVerb, family, tname, buf)
				}
			}
			for _, mname := range sortKeys(table.Maps) {
				m := table.Maps[mname]
				m.writeOperation(addVerb, family, tname, buf)

				for _, element := range m.Elements {
					element.writeOperation(addVerb, family, tname, buf)
				}
			}
		}
	}

	return buf.String()
}

func sortKeys[K ~string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
