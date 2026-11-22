// SPDX-License-Identifier: MIT

package perf

import (
	"reflect"
	"testing"
)

func TestBOMShape(t *testing.T) {
	shape := Shape{Projects: 2, Versions: 3, Components: 100, Fanout: 3}
	bom := BOM(0, 0, shape)
	if !reflect.DeepEqual(bom, BOM(0, 0, shape)) {
		t.Fatal("fixture is not deterministic")
	}
	if len(bom.Components) != shape.Components || len(bom.ComponentInfo) != shape.Components {
		t.Fatal("component population differs from requested shape")
	}
	if BOM(0, 1, shape).ComponentInfo[bom.Components[0]].Version == bom.ComponentInfo[bom.Components[0]].Version {
		t.Fatal("successive versions must contain a diff")
	}
	if BOM(1, 0, shape).Components[0] == bom.Components[0] {
		t.Fatal("projects must have distinguishable populations")
	}
	for from, targets := range bom.Dependency {
		if len(targets) > shape.Fanout {
			t.Fatal("fanout exceeds shape")
		}
		for _, to := range targets {
			if bom.ComponentToLevel[to] != bom.ComponentToLevel[from]+1 {
				t.Fatal("edge does not join consecutive levels")
			}
		}
	}
}
