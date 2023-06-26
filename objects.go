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
	"strconv"
	"strings"
)

// Object implementation for Table
func (table *Table) GetType() string {
	return "table"
}

func (table *Table) GetName() string {
	if table.Name == nil {
		return ""
	}
	return table.Name.Name
}

func (table *Table) GetFamily() Family {
	if table.Name == nil {
		return ""
	}
	return table.Name.Family
}

func (table *Table) GetTable() string {
	if table.Name == nil {
		return ""
	}
	return table.Name.Name
}

func (table *Table) GetHandle() (int, error) {
	if table.Handle == nil {
		return -1, fmt.Errorf("handle not set")
	}
	return *table.Handle, nil
}

func (table *Table) validate(verb verb, defaultFamily Family, defaultTable string) error {
	if table.Name == nil {
		table.Name = &TableName{Family: defaultFamily, Name: defaultTable}
	}

	switch verb {
	case addVerb, flushVerb:
		if table.Handle != nil {
			return fmt.Errorf("cannot specify Handle in %s operation", verb)
		}
	case deleteVerb:
		// Handle can be nil or non-nil
	default:
		return fmt.Errorf("%s is not implemented for tables", verb)
	}

	return nil
}

func (table *Table) writeOperation(verb verb, writer io.Writer) {
	// Special case for delete-by-handle
	if verb == deleteVerb && table.Handle != nil {
		fmt.Fprintf(writer, "delete table %s handle %d", table.Name.Family, *table.Handle)
		return
	}

	// All other cases refer to the table by name
	fmt.Fprintf(writer, "%s table %s %s", verb, table.Name.Family, table.Name.Name)
	if table.Comment != nil {
		fmt.Fprintf(writer, " { comment %q ; }", *table.Comment)
	}
	fmt.Fprintf(writer, "\n")
}

// Object implementation for Chain
func (chain *Chain) GetType() string {
	return "chain"
}

func (chain *Chain) GetName() string {
	return chain.Name
}

func (chain *Chain) GetFamily() Family {
	if chain.Table == nil {
		return ""
	}
	return chain.Table.Family
}

func (chain *Chain) GetTable() string {
	if chain.Table == nil {
		return ""
	}
	return chain.Table.Name
}

func (chain *Chain) GetHandle() (int, error) {
	if chain.Handle == nil {
		return -1, fmt.Errorf("handle not set")
	}
	return *chain.Handle, nil
}

func (chain *Chain) validate(verb verb, defaultFamily Family, defaultTable string) error {
	if chain.Name == "" {
		return fmt.Errorf("no name specified for chain")
	}
	if chain.Table == nil {
		chain.Table = &TableName{Family: defaultFamily, Name: defaultTable}
	}

	if chain.Hook == nil && (chain.Type != nil || chain.Priority != nil) {
		return fmt.Errorf("regular chain %q must not specify Type or Priority", chain.Name)
	} else if chain.Hook != nil && (chain.Type == nil || chain.Priority == nil) {
		return fmt.Errorf("base chain %q must specify Type and Priority", chain.Name)
	}

	if chain.Priority != nil {
		_, err := chain.ParsePriority()
		if err != nil {
			return fmt.Errorf("invalid base chain priority: %v", err)
		}
	}

	switch verb {
	case addVerb, flushVerb:
		if chain.Handle != nil {
			return fmt.Errorf("cannot specify Handle in %s operation", verb)
		}
	case deleteVerb:
		// Handle can be nil or non-nil
	default:
		return fmt.Errorf("%s is not implemented for chains", verb)
	}

	return nil
}

func (chain *Chain) writeOperation(verb verb, writer io.Writer) {
	// Special case for delete-by-handle
	if verb == deleteVerb && chain.Handle != nil {
		fmt.Fprintf(writer, "delete chain %s %s handle %d", chain.Table.Family, chain.Table.Name, *chain.Handle)
		return
	}

	fmt.Fprintf(writer, "%s chain %s %s %s", verb, chain.Table.Family, chain.Table.Name, chain.Name)
	if verb == addVerb && (chain.Type != nil || chain.Comment != nil) {
		fmt.Fprintf(writer, " {")

		if chain.Type != nil {
			fmt.Fprintf(writer, " type %s hook %s priority %s ;", *chain.Type, *chain.Hook, *chain.Priority)
		}
		if chain.Comment != nil {
			fmt.Fprintf(writer, " comment %q ;", *chain.Comment)
		}

		fmt.Fprintf(writer, " }")
	}

	fmt.Fprintf(writer, "\n")
}

var numericPriorities = map[string]int{
	"raw":      -300,
	"mangle":   -150,
	"dstnat":   -100,
	"filter":   0,
	"security": 50,
	"srcnat":   100,
}

var bridgeNumericPriorities = map[string]int{
	"dstnat": -300,
	"filter": -200,
	"out":    100,
	"srcnat": 300,
}

// ParsePriority tries to convert the string form of chain.Priority into a number
func (chain *Chain) ParsePriority() (int, error) {
	if chain.Priority == nil {
		return 0, fmt.Errorf("priority not set for chain %s", chain.Name)
	}
	priority := string(*chain.Priority)
	val, err := strconv.Atoi(priority)
	if err == nil {
		return val, nil
	}

	modVal := 0
	if i := strings.IndexAny(priority, "+-"); i != -1 {
		mod := priority[i:]
		modVal, err = strconv.Atoi(mod)
		if err != nil {
			return 0, fmt.Errorf("could not parse modifier %q: %v", mod, err)
		}
		priority = priority[:i]
	}

	var found bool
	if chain.GetFamily() == BridgeFamily {
		val, found = bridgeNumericPriorities[priority]
	} else {
		val, found = numericPriorities[priority]
	}
	if !found {
		return 0, fmt.Errorf("unknown priority %q", priority)
	}

	return val + modVal, nil
}

// Object implementation for Rule
func (rule *Rule) GetType() string {
	return "rule"
}

func (rule *Rule) GetName() string {
	return rule.Chain
}

func (rule *Rule) GetFamily() Family {
	if rule.Table == nil {
		return ""
	}
	return rule.Table.Family
}

func (rule *Rule) GetTable() string {
	if rule.Table == nil {
		return ""
	}
	return rule.Table.Name
}

func (rule *Rule) GetHandle() (int, error) {
	if rule.Handle == nil {
		return -1, fmt.Errorf("handle not set")
	}
	return *rule.Handle, nil
}

func (rule *Rule) validate(verb verb, defaultFamily Family, defaultTable string) error {
	if rule.Chain == "" {
		return fmt.Errorf("no chain name specified for rule")
	}
	if rule.Table == nil {
		rule.Table = &TableName{Family: defaultFamily, Name: defaultTable}
	}

	if rule.Index != nil && rule.Handle != nil {
		return fmt.Errorf("cannot specify both Index and Handle")
	}

	if (verb == deleteVerb || verb == replaceVerb) && rule.Handle == nil {
		return fmt.Errorf("must specify Handle with %s", verb)
	}

	return nil
}

func (rule *Rule) writeOperation(verb verb, writer io.Writer) {
	fmt.Fprintf(writer, "%s rule %s %s %s", verb, rule.Table.Family, rule.Table.Name, rule.Chain)
	if rule.Index != nil {
		fmt.Fprintf(writer, " index %d", *rule.Index)
	} else if rule.Handle != nil {
		fmt.Fprintf(writer, " handle %d", *rule.Index)
	}

	switch verb {
	case addVerb, insertVerb, replaceVerb:
		fmt.Fprintf(writer, " %s", rule.Rule)

		if rule.Comment != nil {
			fmt.Fprintf(writer, " comment %q", *rule.Comment)
		}
	}

	fmt.Fprintf(writer, "\n")
}

// Object implementation for Set
func (set *Set) GetType() string {
	return "set"
}

func (set *Set) GetName() string {
	return set.Name
}

func (set *Set) GetFamily() Family {
	if set.Table == nil {
		return ""
	}
	return set.Table.Family
}

func (set *Set) GetTable() string {
	if set.Table == nil {
		return ""
	}
	return set.Table.Name
}

func (set *Set) GetHandle() (int, error) {
	if set.Handle == nil {
		return -1, fmt.Errorf("handle not set")
	}
	return *set.Handle, nil
}

func (set *Set) validate(verb verb, defaultFamily Family, defaultTable string) error {
	if set.Name == "" {
		return fmt.Errorf("no name specified for set")
	}
	if set.Table == nil {
		set.Table = &TableName{Family: defaultFamily, Name: defaultTable}
	}

	switch verb {
	case addVerb:
		if (set.Type == "" && set.TypeOf == "") || (set.Type != "" && set.TypeOf != "") {
			return fmt.Errorf("set must specify either Type or TypeOf")
		}
		fallthrough
	case flushVerb:
		if set.Handle != nil {
			return fmt.Errorf("cannot specify Handle in %s operation", verb)
		}
	case deleteVerb:
		// Handle can be nil or non-nil
	default:
		return fmt.Errorf("%s is not implemented for sets", verb)
	}

	return nil
}

func (set *Set) writeOperation(verb verb, writer io.Writer) {
	// Special case for delete-by-handle
	if verb == deleteVerb && set.Handle != nil {
		fmt.Fprintf(writer, "delete set %s %s handle %d", set.Table.Family, set.Table.Name, *set.Handle)
		return
	}

	fmt.Fprintf(writer, "%s set %s %s %s", verb, set.Table.Family, set.Table.Name, set.Name)
	if verb == addVerb {
		fmt.Fprintf(writer, " {")

		if set.Type != "" {
			fmt.Fprintf(writer, " type %s ;", set.Type)
		} else {
			fmt.Fprintf(writer, " typeof %s ;", set.TypeOf)
		}

		if len(set.Flags) != 0 {
			fmt.Fprintf(writer, " flags ")
			for i := range set.Flags {
				if i > 0 {
					fmt.Fprintf(writer, ",")
				}
				fmt.Fprintf(writer, "%s", set.Flags[i])
			}
			fmt.Fprintf(writer, " ;")
		}

		if set.Timeout != nil {
			fmt.Fprintf(writer, " timeout %d ;", int64(set.Timeout.Seconds()))
		}
		if set.GCInterval != nil {
			fmt.Fprintf(writer, " gc-interval %d ;", int64(set.GCInterval.Seconds()))
		}
		if set.Size != nil {
			fmt.Fprintf(writer, " size %d ;", *set.Size)
		}
		if set.Policy != nil {
			fmt.Fprintf(writer, " policy %s ;", *set.Policy)
		}
		if set.AutoMerge != nil && *set.AutoMerge {
			fmt.Fprintf(writer, " auto-merge ;")
		}

		if set.Comment != nil {
			fmt.Fprintf(writer, " comment %q ;", *set.Comment)
		}

		fmt.Fprintf(writer, " }")
	}

	fmt.Fprintf(writer, "\n")
}

// Object implementation for Set
func (mapObj *Map) GetType() string {
	return "map"
}

func (mapObj *Map) GetName() string {
	return mapObj.Name
}

func (mapObj *Map) GetFamily() Family {
	if mapObj.Table == nil {
		return ""
	}
	return mapObj.Table.Family
}

func (mapObj *Map) GetTable() string {
	if mapObj.Table == nil {
		return ""
	}
	return mapObj.Table.Name
}

func (mapObj *Map) GetHandle() (int, error) {
	if mapObj.Handle == nil {
		return -1, fmt.Errorf("handle not set")
	}
	return *mapObj.Handle, nil
}

func (mapObj *Map) validate(verb verb, defaultFamily Family, defaultTable string) error {
	if mapObj.Name == "" {
		return fmt.Errorf("no name specified for map")
	}
	if mapObj.Table == nil {
		mapObj.Table = &TableName{Family: defaultFamily, Name: defaultTable}
	}

	switch verb {
	case addVerb:
		if (mapObj.Type == "" && mapObj.TypeOf == "") || (mapObj.Type != "" && mapObj.TypeOf != "") {
			return fmt.Errorf("map must specify either Type or TypeOf")
		}
		fallthrough
	case flushVerb:
		if mapObj.Handle != nil {
			return fmt.Errorf("cannot specify Handle in %s operation", verb)
		}
	case deleteVerb:
		// Handle can be nil or non-nil
	default:
		return fmt.Errorf("%s is not implemented for maps", verb)
	}

	return nil
}

func (mapObj *Map) writeOperation(verb verb, writer io.Writer) {
	// Special case for delete-by-handle
	if verb == deleteVerb && mapObj.Handle != nil {
		fmt.Fprintf(writer, "delete map %s %s handle %d", mapObj.Table.Family, mapObj.Table.Name, *mapObj.Handle)
		return
	}

	fmt.Fprintf(writer, "%s map %s %s %s", verb, mapObj.Table.Family, mapObj.Table.Name, mapObj.Name)
	if verb == addVerb {
		fmt.Fprintf(writer, " {")

		if mapObj.Type != "" {
			fmt.Fprintf(writer, " type %s ;", mapObj.Type)
		} else {
			fmt.Fprintf(writer, " typeof %s ;", mapObj.TypeOf)
		}

		if len(mapObj.Flags) != 0 {
			fmt.Fprintf(writer, " flags ")
			for i := range mapObj.Flags {
				if i > 0 {
					fmt.Fprintf(writer, ",")
				}
				fmt.Fprintf(writer, "%s", mapObj.Flags[i])
			}
			fmt.Fprintf(writer, " ;")
		}

		if mapObj.Timeout != nil {
			fmt.Fprintf(writer, " timeout %d ;", int64(mapObj.Timeout.Seconds()))
		}
		if mapObj.GCInterval != nil {
			fmt.Fprintf(writer, " gc-interval %d ;", int64(mapObj.GCInterval.Seconds()))
		}
		if mapObj.Size != nil {
			fmt.Fprintf(writer, " size %d ;", *mapObj.Size)
		}
		if mapObj.Policy != nil {
			fmt.Fprintf(writer, " policy %s ;", *mapObj.Policy)
		}

		if mapObj.Comment != nil {
			fmt.Fprintf(writer, " comment %q ;", *mapObj.Comment)
		}

		fmt.Fprintf(writer, " }")
	}

	fmt.Fprintf(writer, "\n")
}

// Object implementation for Element
func (element *Element) GetType() string {
	return "element"
}

func (element *Element) GetName() string {
	return element.Name
}

func (element *Element) GetFamily() Family {
	if element.Table == nil {
		return ""
	}
	return element.Table.Family
}

func (element *Element) GetTable() string {
	if element.Table == nil {
		return ""
	}
	return element.Table.Name
}

func (element *Element) GetHandle() (int, error) {
	return -1, fmt.Errorf("Elements do not have handles")
}

func (element *Element) validate(verb verb, defaultFamily Family, defaultTable string) error {
	if element.Name == "" {
		return fmt.Errorf("no set/map name specified for element")
	}
	if element.Table == nil {
		element.Table = &TableName{Family: defaultFamily, Name: defaultTable}
	}

	return nil
}

func (element *Element) writeOperation(verb verb, writer io.Writer) {
	fmt.Fprintf(writer, "%s element %s %s %s { %s", verb, element.Table.Family, element.Table.Name, element.Name, element.Key)

	if element.Value != "" {
		fmt.Fprintf(writer, " : %s", element.Value)
	}

	if verb == addVerb && element.Comment != nil {
		fmt.Fprintf(writer, " comment %q", *element.Comment)
	}

	fmt.Fprintf(writer, " }\n")
}
