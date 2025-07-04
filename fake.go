/*
Copyright 2023 The Kubernetes Authors.

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
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Fake is a fake implementation of Interface
type Fake struct {
	nftContext
	// mutex is used to protect Table/Tables and LastTransaction.
	// When Table/Tables and LastTransaction are accessed directly, the caller must
	// acquire Fake.RLock and release when finished.
	sync.RWMutex

	nextHandle int

	// Table contains the Interface's table (assuming the Fake has a default table).
	// This will be `nil` until you `tx.Add()` the table.
	// Make sure to acquire Fake.RLock before accessing Table in a concurrent environment.
	Table *FakeTable

	// Tables contains all tables known to Fake. This will be empty until you
	// `tx.Add()` a table.
	// Make sure to acquire Fake.RLock before accessing Tables in a concurrent environment.
	Tables map[Family]map[string]*FakeTable

	// LastTransaction is the last transaction passed to Run(). It will remain set until the
	// next time Run() is called. (It is not affected by Check().)
	// Make sure to acquire Fake.RLock before accessing LastTransaction in a
	// concurrent environment.
	LastTransaction *Transaction
}

// FakeTable wraps Table for the Fake implementation
type FakeTable struct {
	Table

	// Flowtables contains the table's flowtables, keyed by name
	Flowtables map[string]*FakeFlowtable

	// Chains contains the table's chains, keyed by name
	Chains map[string]*FakeChain

	// Sets contains the table's sets, keyed by name
	Sets map[string]*FakeSet

	// Maps contains the table's maps, keyed by name
	Maps map[string]*FakeMap

	// Counters contains the table's counters, keyed by name
	Counters map[string]*FakeCounter
}

// FakeFlowtable wraps Flowtable for the Fake implementation
type FakeFlowtable struct {
	Flowtable
}

// FakeCounter wraps Counter for the Fake implementation
type FakeCounter struct {
	Counter
}

// FakeChain wraps Chain for the Fake implementation
type FakeChain struct {
	Chain

	// Rules contains the chain's rules, in order
	Rules []*Rule
}

// FakeSet wraps Set for the Fake implementation
type FakeSet struct {
	Set

	// Elements contains the set's elements. You can also use the FakeSet's
	// FindElement() method to see if a particular element is present.
	Elements []*Element
}

// FakeMap wraps Set for the Fake implementation
type FakeMap struct {
	Map

	// Elements contains the map's elements. You can also use the FakeMap's
	// FindElement() method to see if a particular element is present.
	Elements []*Element
}

// NewFake creates a new fake Interface, for unit tests
func NewFake(family Family, table string) *Fake {
	if (family == "") != (table == "") {
		// NewFake doesn't have an error return value, so...
		panic("family and table must either both be specified or both be empty")
	}

	return &Fake{
		nftContext: nftContext{
			family: family,
			table:  table,
		},
	}
}

var _ Interface = &Fake{}

// List is part of Interface.
func (fake *Fake) List(_ context.Context, objectType string) ([]string, error) {
	fake.RLock()
	defer fake.RUnlock()
	if fake.Table == nil {
		return nil, notFoundError("no such table %q", fake.table)
	}

	var result []string

	switch objectType {
	case "flowtable", "flowtables":
		for name := range fake.Table.Flowtables {
			result = append(result, name)
		}
	case "chain", "chains":
		for name := range fake.Table.Chains {
			result = append(result, name)
		}
	case "set", "sets":
		for name := range fake.Table.Sets {
			result = append(result, name)
		}
	case "map", "maps":
		for name := range fake.Table.Maps {
			result = append(result, name)
		}
	case "counter", "counters":
		for name := range fake.Table.Counters {
			result = append(result, name)
		}

	default:
		return nil, fmt.Errorf("unsupported object type %q", objectType)
	}

	return result, nil
}

// ListRules is part of Interface
func (fake *Fake) ListRules(_ context.Context, chain string) ([]*Rule, error) {
	fake.RLock()
	defer fake.RUnlock()
	if fake.Table == nil {
		return nil, notFoundError("no such table %q", fake.table)
	}

	rules := []*Rule{}
	if chain == "" {
		// Include all rules across all chains.
		for _, ch := range fake.Table.Chains {
			rules = append(rules, ch.Rules...)
		}
	} else {
		ch := fake.Table.Chains[chain]
		if ch == nil {
			return nil, notFoundError("no such chain %q", chain)
		}
		rules = append(rules, ch.Rules...)
	}
	return rules, nil
}

// ListElements is part of Interface
func (fake *Fake) ListElements(_ context.Context, objectType, name string) ([]*Element, error) {
	fake.RLock()
	defer fake.RUnlock()
	if fake.Table == nil {
		return nil, notFoundError("no such %s %q", objectType, name)
	}
	if objectType == "set" {
		s := fake.Table.Sets[name]
		if s != nil {
			return s.Elements, nil
		}
	} else if objectType == "map" {
		m := fake.Table.Maps[name]
		if m != nil {
			return m.Elements, nil
		}
	}
	return nil, notFoundError("no such %s %q", objectType, name)
}

// NewTransaction is part of Interface
func (fake *Fake) NewTransaction() *Transaction {
	return &Transaction{nftContext: &fake.nftContext}
}

// Run is part of Interface
func (fake *Fake) Run(_ context.Context, tx *Transaction) error {
	fake.Lock()
	defer fake.Unlock()
	fake.LastTransaction = tx
	updatedTables, err := fake.run(tx)
	if err == nil {
		fake.Tables = updatedTables
		if fake.family != "" && fake.table != "" {
			fake.Table = updatedTables[fake.family][fake.table]
		}
	}
	return err
}

// Check is part of Interface
func (fake *Fake) Check(_ context.Context, tx *Transaction) error {
	fake.RLock()
	defer fake.RUnlock()
	_, err := fake.run(tx)
	return err
}

// must be called with fake.lock held
func (fake *Fake) run(tx *Transaction) (map[Family]map[string]*FakeTable, error) {
	if tx.err != nil {
		return nil, tx.err
	}

	updatedTables := make(map[Family]map[string]*FakeTable)
	for family := range fake.Tables {
		updatedTables[family] = make(map[string]*FakeTable)
		for name, table := range fake.Tables[family] {
			updatedTables[family][name] = table.copy()
		}
	}

	for _, op := range tx.operations {
		if op.verb == addVerb || op.verb == createVerb || op.verb == insertVerb {
			fake.nextHandle++
		}

		switch obj := op.obj.(type) {
		case *Table:
			family, tableName, _ := getTable(&fake.nftContext, obj.Family, obj.Name)
			table := updatedTables[family][tableName]
			err := checkExists(op.verb, "table", fake.table, table != nil)
			if err != nil {
				return nil, err
			}
			switch op.verb {
			case flushVerb:
				table = nil
				fallthrough
			case addVerb, createVerb:
				if table != nil {
					continue
				}
				table = &FakeTable{
					Table:      *obj,
					Flowtables: make(map[string]*FakeFlowtable),
					Chains:     make(map[string]*FakeChain),
					Sets:       make(map[string]*FakeSet),
					Maps:       make(map[string]*FakeMap),
					Counters:   make(map[string]*FakeCounter),
				}
				table.Handle = PtrTo(fake.nextHandle)
				if updatedTables[family] == nil {
					updatedTables[family] = make(map[string]*FakeTable)
				}
				updatedTables[family][tableName] = table
			case deleteVerb, destroyVerb:
				if table != nil {
					delete(updatedTables[family], tableName)
				}
			default:
				return nil, fmt.Errorf("unhandled operation %q", op.verb)
			}

		case *Flowtable:
			family, tableName, _ := getTable(&fake.nftContext, obj.Family, obj.Table)
			table, err := fake.checkTable(updatedTables, family, tableName)
			if err != nil {
				return nil, err
			}
			existingFlowtable := table.Flowtables[obj.Name]
			err = checkExists(op.verb, "flowtable", obj.Name, existingFlowtable != nil)
			if err != nil {
				return nil, err
			}
			switch op.verb {
			case addVerb, createVerb:
				if existingFlowtable != nil {
					continue
				}
				flowtable := *obj
				flowtable.Handle = PtrTo(fake.nextHandle)
				table.Flowtables[obj.Name] = &FakeFlowtable{
					Flowtable: flowtable,
				}
			case deleteVerb, destroyVerb:
				// FIXME delete-by-handle
				delete(table.Flowtables, obj.Name)
			default:
				return nil, fmt.Errorf("unhandled operation %q", op.verb)
			}

		case *Chain:
			family, tableName, _ := getTable(&fake.nftContext, obj.Family, obj.Table)
			table, err := fake.checkTable(updatedTables, family, tableName)
			if err != nil {
				return nil, err
			}
			existingChain := table.Chains[obj.Name]
			err = checkExists(op.verb, "chain", obj.Name, existingChain != nil)
			if err != nil {
				return nil, err
			}
			switch op.verb {
			case addVerb, createVerb:
				if existingChain != nil {
					continue
				}
				chain := *obj
				chain.Handle = PtrTo(fake.nextHandle)
				table.Chains[obj.Name] = &FakeChain{
					Chain: chain,
				}
			case flushVerb:
				existingChain.Rules = nil
			case deleteVerb, destroyVerb:
				// FIXME delete-by-handle
				delete(table.Chains, obj.Name)
			default:
				return nil, fmt.Errorf("unhandled operation %q", op.verb)
			}

		case *Rule:
			family, tableName, _ := getTable(&fake.nftContext, obj.Family, obj.Table)
			table, err := fake.checkTable(updatedTables, family, tableName)
			if err != nil {
				return nil, err
			}
			existingChain := table.Chains[obj.Chain]
			if existingChain == nil {
				return nil, notFoundError("no such chain %q", obj.Chain)
			}
			if op.verb == deleteVerb {
				i := findRule(existingChain.Rules, *obj.Handle)
				if i == -1 {
					return nil, notFoundError("no rule with handle %d", *obj.Handle)
				}
				existingChain.Rules = append(existingChain.Rules[:i], existingChain.Rules[i+1:]...)
				continue
			}

			rule := *obj
			refRule := -1
			if rule.Handle != nil {
				refRule = findRule(existingChain.Rules, *obj.Handle)
				if refRule == -1 {
					return nil, notFoundError("no rule with handle %d", *obj.Handle)
				}
			} else if obj.Index != nil {
				if *obj.Index >= len(existingChain.Rules) {
					return nil, notFoundError("no rule with index %d", *obj.Index)
				}
				refRule = *obj.Index
			}

			if err := checkRuleRefs(obj, table); err != nil {
				return nil, err
			}

			switch op.verb {
			case addVerb:
				if refRule == -1 {
					existingChain.Rules = append(existingChain.Rules, &rule)
				} else {
					existingChain.Rules = append(existingChain.Rules[:refRule+1], append([]*Rule{&rule}, existingChain.Rules[refRule+1:]...)...)
				}
				rule.Handle = PtrTo(fake.nextHandle)
			case insertVerb:
				if refRule == -1 {
					existingChain.Rules = append([]*Rule{&rule}, existingChain.Rules...)
				} else {
					existingChain.Rules = append(existingChain.Rules[:refRule], append([]*Rule{&rule}, existingChain.Rules[refRule:]...)...)
				}
				rule.Handle = PtrTo(fake.nextHandle)
			case replaceVerb:
				existingChain.Rules[refRule] = &rule
			default:
				return nil, fmt.Errorf("unhandled operation %q", op.verb)
			}

		case *Set:
			family, tableName, _ := getTable(&fake.nftContext, obj.Family, obj.Table)
			table, err := fake.checkTable(updatedTables, family, tableName)
			if err != nil {
				return nil, err
			}
			existingSet := table.Sets[obj.Name]
			err = checkExists(op.verb, "set", obj.Name, existingSet != nil)
			if err != nil {
				return nil, err
			}
			switch op.verb {
			case addVerb, createVerb:
				if existingSet != nil {
					continue
				}
				set := *obj
				set.Handle = PtrTo(fake.nextHandle)
				table.Sets[obj.Name] = &FakeSet{
					Set: set,
				}
			case flushVerb:
				existingSet.Elements = nil
			case deleteVerb, destroyVerb:
				// FIXME delete-by-handle
				delete(table.Sets, obj.Name)
			default:
				return nil, fmt.Errorf("unhandled operation %q", op.verb)
			}
		case *Map:
			family, tableName, _ := getTable(&fake.nftContext, obj.Family, obj.Table)
			table, err := fake.checkTable(updatedTables, family, tableName)
			if err != nil {
				return nil, err
			}
			existingMap := table.Maps[obj.Name]
			err = checkExists(op.verb, "map", obj.Name, existingMap != nil)
			if err != nil {
				return nil, err
			}
			switch op.verb {
			case addVerb:
				if existingMap != nil {
					continue
				}
				mapObj := *obj
				mapObj.Handle = PtrTo(fake.nextHandle)
				table.Maps[obj.Name] = &FakeMap{
					Map: mapObj,
				}
			case flushVerb:
				existingMap.Elements = nil
			case deleteVerb, destroyVerb:
				// FIXME delete-by-handle
				delete(table.Maps, obj.Name)
			default:
				return nil, fmt.Errorf("unhandled operation %q", op.verb)
			}
		case *Element:
			family, tableName, _ := getTable(&fake.nftContext, obj.Family, obj.Table)
			table, err := fake.checkTable(updatedTables, family, tableName)
			if err != nil {
				return nil, err
			}
			if obj.Set != "" {
				existingSet := table.Sets[obj.Set]
				if existingSet == nil {
					return nil, notFoundError("no such set %q", obj.Set)
				}
				switch op.verb {
				case addVerb, createVerb:
					element := *obj
					if i := findElement(existingSet.Elements, element.Key); i != -1 {
						if op.verb == createVerb {
							return nil, existsError("element %q already exists", strings.Join(element.Key, " . "))
						}
						existingSet.Elements[i] = &element
					} else {
						existingSet.Elements = append(existingSet.Elements, &element)
					}
				case deleteVerb, destroyVerb:
					element := *obj
					if i := findElement(existingSet.Elements, element.Key); i != -1 {
						existingSet.Elements = append(existingSet.Elements[:i], existingSet.Elements[i+1:]...)
					} else if op.verb == deleteVerb {
						return nil, notFoundError("no such element %q", strings.Join(element.Key, " . "))
					}
				default:
					return nil, fmt.Errorf("unhandled operation %q", op.verb)
				}
			} else {
				existingMap := table.Maps[obj.Map]
				if existingMap == nil {
					return nil, notFoundError("no such map %q", obj.Map)
				}
				if err := checkElementRefs(obj, table); err != nil {
					return nil, err
				}
				switch op.verb {
				case addVerb, createVerb:
					element := *obj
					if i := findElement(existingMap.Elements, element.Key); i != -1 {
						if op.verb == createVerb {
							return nil, existsError("element %q already exists", strings.Join(element.Key, ". "))
						}
						existingMap.Elements[i] = &element
					} else {
						existingMap.Elements = append(existingMap.Elements, &element)
					}
				case deleteVerb, destroyVerb:
					element := *obj
					if i := findElement(existingMap.Elements, element.Key); i != -1 {
						existingMap.Elements = append(existingMap.Elements[:i], existingMap.Elements[i+1:]...)
					} else if op.verb == deleteVerb {
						return nil, notFoundError("no such element %q", strings.Join(element.Key, " . "))
					}
				default:
					return nil, fmt.Errorf("unhandled operation %q", op.verb)
				}
			}
		case *Counter:
			family, tableName, _ := getTable(&fake.nftContext, obj.Family, obj.Table)
			table, err := fake.checkTable(updatedTables, family, tableName)
			if err != nil {
				return nil, err
			}
			existingCounter := table.Counters[obj.Name]
			switch op.verb {
			case addVerb, createVerb:
				err := checkExists(op.verb, "counter", obj.Name, existingCounter != nil)
				if err != nil {
					return nil, err
				}
				if existingCounter != nil {
					continue
				}
				obj.Handle = PtrTo(fake.nextHandle)
				table.Counters[obj.Name] = &FakeCounter{*obj}
			case resetVerb:
				err := checkExists(op.verb, "counter", obj.Name, existingCounter != nil)
				if err != nil {
					return nil, err
				}
				table.Counters[obj.Name].Packets = PtrTo[uint64](0)
				table.Counters[obj.Name].Bytes = PtrTo[uint64](0)
			case deleteVerb:
				if obj.Handle != nil {
					var found bool
					for _, counter := range table.Counters {
						if *counter.Handle == *obj.Handle {
							found = true
							delete(table.Counters, counter.Name)
							break
						}
					}
					if !found {
						return nil, notFoundError("no such counter %q", obj.Name)
					}
				} else {
					err := checkExists(op.verb, "counter", obj.Name, existingCounter != nil)
					if err != nil {
						return nil, err
					}
					delete(table.Counters, obj.Name)
				}
			default:
				return nil, fmt.Errorf("unhandled operation %q", op.verb)
			}
		default:
			return nil, fmt.Errorf("unhandled object type %T", op.obj)
		}
	}

	return updatedTables, nil
}

func (fake *Fake) checkTable(updatedTables map[Family]map[string]*FakeTable, family Family, tableName string) (*FakeTable, error) {
	table := updatedTables[family][tableName]
	if table == nil {
		return nil, notFoundError("no such table \"%s\" \"%s\"", family, tableName)
	}
	return table, nil
}

func checkExists(verb verb, objectType, name string, exists bool) error {
	switch verb {
	case addVerb, destroyVerb:
		// It's fine if the object either exists or doesn't
		return nil
	case createVerb:
		if exists {
			return existsError("%s %q already exists", objectType, name)
		}
	default:
		if !exists {
			return notFoundError("no such %s %q", objectType, name)
		}
	}
	return nil
}

// checkRuleRefs checks for chains, sets, and maps referenced by rule in table
func checkRuleRefs(rule *Rule, table *FakeTable) error {
	words := strings.Split(rule.Rule, " ")
	for i, word := range words {
		if strings.HasPrefix(word, "@") && !strings.Contains(word, ",") {
			name := word[1:]
			if i > 0 && (words[i-1] == "map" || words[i-1] == "vmap") {
				if table.Maps[name] == nil {
					return notFoundError("no such map %q", name)
				}
			} else if i > 0 && words[i-1] == "offload" {
				if table.Flowtables[name] == nil {
					return notFoundError("no such flowtable %q", name)
				}
			} else {
				// recent nft lets you use a map in a set lookup
				if table.Sets[name] == nil && table.Maps[name] == nil {
					return notFoundError("no such set %q", name)
				}
			}
		} else if (word == "goto" || word == "jump") && i < len(words)-1 {
			name := words[i+1]
			if table.Chains[name] == nil {
				return notFoundError("no such chain %q", name)
			}
		}
	}
	return nil
}

// checkElementRefs checks for chains referenced by an element
func checkElementRefs(element *Element, table *FakeTable) error {
	if len(element.Value) != 1 {
		return nil
	}
	words := strings.Split(element.Value[0], " ")
	if len(words) == 2 && (words[0] == "goto" || words[0] == "jump") {
		name := words[1]
		if table.Chains[name] == nil {
			return notFoundError("no such chain %q", name)
		}
	}
	return nil
}

// Dump dumps the current contents of fake, in a way that looks like an nft transaction.
func (fake *Fake) Dump() string {
	fake.RLock()
	defer fake.RUnlock()

	buf := &strings.Builder{}
	for _, family := range sortKeys(fake.Tables) {
		for _, tableName := range sortKeys(fake.Tables[family]) {
			fake.dumpTable(buf, fake.Tables[family][tableName])
		}
	}
	return buf.String()
}

func (fake *Fake) dumpTable(buf *strings.Builder, table *FakeTable) {
	flowtables := sortKeys(table.Flowtables)
	chains := sortKeys(table.Chains)
	sets := sortKeys(table.Sets)
	maps := sortKeys(table.Maps)
	counters := sortKeys(table.Counters)

	// Write out all of the object adds first.

	table.writeOperation(addVerb, &fake.nftContext, buf)
	for _, fname := range flowtables {
		ft := table.Flowtables[fname]
		ft.writeOperation(addVerb, &fake.nftContext, buf)
	}
	for _, cname := range chains {
		ch := table.Chains[cname]
		ch.writeOperation(addVerb, &fake.nftContext, buf)
	}
	for _, sname := range sets {
		s := table.Sets[sname]
		s.writeOperation(addVerb, &fake.nftContext, buf)
	}
	for _, mname := range maps {
		m := table.Maps[mname]
		m.writeOperation(addVerb, &fake.nftContext, buf)
	}
	for _, cname := range counters {
		m := table.Counters[cname]
		m.writeOperation(addVerb, &fake.nftContext, buf)
	}
	// Now write their contents.

	for _, cname := range chains {
		ch := table.Chains[cname]
		for _, rule := range ch.Rules {
			// Avoid outputing handles
			dumpRule := *rule
			dumpRule.Handle = nil
			dumpRule.Index = nil
			dumpRule.writeOperation(addVerb, &fake.nftContext, buf)
		}
	}
	for _, sname := range sets {
		s := table.Sets[sname]
		for _, element := range s.Elements {
			element.writeOperation(addVerb, &fake.nftContext, buf)
		}
	}
	for _, mname := range maps {
		m := table.Maps[mname]
		for _, element := range m.Elements {
			element.writeOperation(addVerb, &fake.nftContext, buf)
		}
	}
}

var commonRegexp = regexp.MustCompile(`add ([^ ]*) ([^ ]*) ([^ ]*)( (.*))?`)

// ParseDump can parse a dump for a given nft instance.
// It expects fake's table name and family in all rules.
// The best way to verify that everything important was properly parsed is to
// compare given data with nft.Dump() output.
func (fake *Fake) ParseDump(data string) (err error) {
	lines := strings.Split(data, "\n")
	var i int
	var line string
	parsingDone := false
	defer func() {
		if err != nil && !parsingDone {
			err = fmt.Errorf("%w (at line %v: %s", err, i+1, line)
		}
	}()
	tx := fake.NewTransaction()

	for i, line = range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		match := commonRegexp.FindStringSubmatch(line)
		if match == nil {
			return fmt.Errorf("could not parse")
		}
		family := Family(match[2])
		table := match[3]

		// If fake has a family and table specified then the parsed family and
		// table must match (but then we clear them, because we don't want them
		// to be added to the returned objects, for backward compatibility).
		if fake.family != "" {
			if family != fake.family {
				return fmt.Errorf("wrong family %q in rule", family)
			}
			family = ""
		}
		if fake.table != "" {
			if table != fake.table {
				return fmt.Errorf("wrong table name %q in rule", table)
			}
			table = ""
		}

		var obj Object
		switch match[1] {
		case "table":
			obj = &Table{}
		case "flowtable":
			obj = &Flowtable{}
		case "chain":
			obj = &Chain{}
		case "rule":
			obj = &Rule{}
		case "map":
			obj = &Map{}
		case "set":
			obj = &Set{}
		case "element":
			obj = &Element{}
		case "counter":
			obj = &Counter{}
		default:
			return fmt.Errorf("unknown object %s", match[1])
		}
		err = obj.parse(family, table, match[5])
		if err != nil {
			return err
		}
		tx.Add(obj)
	}
	parsingDone = true
	return fake.Run(context.Background(), tx)
}

func sortKeys[K ~string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

func findRule(rules []*Rule, handle int) int {
	for i := range rules {
		if rules[i].Handle != nil && *rules[i].Handle == handle {
			return i
		}
	}
	return -1
}

func findElement(elements []*Element, key []string) int {
	for i := range elements {
		if reflect.DeepEqual(elements[i].Key, key) {
			return i
		}
	}
	return -1
}

// copy creates a copy of table with new arrays/maps so we can perform a transaction
// on it without changing the original table.
func (table *FakeTable) copy() *FakeTable {
	if table == nil {
		return nil
	}

	tcopy := &FakeTable{
		Table:      table.Table,
		Flowtables: make(map[string]*FakeFlowtable),
		Chains:     make(map[string]*FakeChain),
		Sets:       make(map[string]*FakeSet),
		Maps:       make(map[string]*FakeMap),
		Counters:   make(map[string]*FakeCounter),
	}
	for name, flowtable := range table.Flowtables {
		tcopy.Flowtables[name] = &FakeFlowtable{
			Flowtable: flowtable.Flowtable,
		}
	}
	for name, chain := range table.Chains {
		tcopy.Chains[name] = &FakeChain{
			Chain: chain.Chain,
			Rules: append([]*Rule{}, chain.Rules...),
		}
	}
	for name, set := range table.Sets {
		tcopy.Sets[name] = &FakeSet{
			Set:      set.Set,
			Elements: append([]*Element{}, set.Elements...),
		}
	}
	for name, mapObj := range table.Maps {
		tcopy.Maps[name] = &FakeMap{
			Map:      mapObj.Map,
			Elements: append([]*Element{}, mapObj.Elements...),
		}
	}
	for name, counter := range table.Counters {
		tcopy.Counters[name] = counter
	}
	return tcopy
}

// FindElement finds an element of the set with the given key. If there is no matching
// element, it returns nil.
func (s *FakeSet) FindElement(key ...string) *Element {
	index := findElement(s.Elements, key)
	if index == -1 {
		return nil
	}
	return s.Elements[index]
}

// FindElement finds an element of the map with the given key. If there is no matching
// element, it returns nil.
func (m *FakeMap) FindElement(key ...string) *Element {
	index := findElement(m.Elements, key)
	if index == -1 {
		return nil
	}
	return m.Elements[index]
}

// ListCounters is part of Interface
func (fake *Fake) ListCounters(_ context.Context) ([]*Counter, error) {
	counters := make([]*Counter, len(fake.Table.Counters))
	for _, fakeCounter := range fake.Table.Counters {
		counters = append(counters, PtrTo(fakeCounter.Counter))
	}
	return counters, nil
}
