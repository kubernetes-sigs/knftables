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
	"net"
	"testing"
)

func TestConcat(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.2.0.0/24")

	for _, tc := range []struct {
		name   string
		values []interface{}
		out    string
	}{
		{
			name:   "empty",
			values: nil,
			out:    "",
		},
		{
			name: "one string",
			values: []interface{}{
				"foo",
			},
			out: "foo",
		},
		{
			name: "one array",
			values: []interface{}{
				[]string{"foo", "bar", "baz"},
			},
			out: "foo bar baz",
		},
		{
			name: "mixed",
			values: []interface{}{
				"foo", []string{"bar", "baz"}, "quux",
			},
			out: "foo bar baz quux",
		},
		{
			name: "empty array",
			values: []interface{}{
				"foo", []string{}, "bar", "baz",
			},
			// no extra spaces
			out: "foo bar baz",
		},
		{
			name: "numbers",
			values: []interface{}{
				1, uint16(65535), int64(-123456789),
			},
			out: "1 65535 -123456789",
		},
		{
			name: "everything",
			values: []interface{}{
				IPv4Family, "saddr", cidr,
				[]string{},
				"th port", 8080,
				[]string{"ct", "state", "established"},
				"drop",
			},
			out: "ip saddr 10.2.0.0/24 th port 8080 ct state established drop",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := Concat(tc.values...)
			if out != tc.out {
				t.Errorf("expected %q got %q", tc.out, out)
			}
		})
	}
}
