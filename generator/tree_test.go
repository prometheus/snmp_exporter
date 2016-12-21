package main

import (
	"reflect"
	"testing"
)

func TestOidToList(t *testing.T) {
	cases := []struct {
		in  *Node
		out *Node
	}{
		// Descriptions trimmed.
		{
			in:  &Node{Oid: "1", Description: "A long   sentance.      Even more detail!"},
			out: &Node{Oid: "1", Description: "A long sentance"},
		},
		// Indexes copied down.
		{
			in: &Node{Oid: "1", Label: "labelEntry", Indexes: []string{"myIndex"},
				Children: []*Node{
					{Oid: "1.1", Label: "labelA"}},
			},
			out: &Node{Oid: "1", Label: "labelEntry", Indexes: []string{"myIndex"},
				Children: []*Node{
					{Oid: "1.1", Label: "labelA", Indexes: []string{"myIndex"}}},
			},
		},
		// Augemnts copied over.
		{
			in: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableDesc"},
								Children: []*Node{
									{Oid: "1.1.1.1", Label: "tableDesc"}}}}},
					{Oid: "1.2", Label: "augmentingTable",
						Children: []*Node{
							{Oid: "1.2.1", Label: "augmentingTableEntry", Augments: "tableEntry",
								Children: []*Node{
									{Oid: "1.2.1.1", Label: "augmentingA"}}}}},
				},
			},
			out: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableDesc"},
								Children: []*Node{
									{Oid: "1.1.1.1", Label: "tableDesc", Indexes: []string{"tableDesc"}}}}}},
					{Oid: "1.2", Label: "augmentingTable",
						Children: []*Node{
							{Oid: "1.2.1", Label: "augmentingTableEntry", Augments: "tableEntry", Indexes: []string{"tableDesc"},
								Children: []*Node{
									{Oid: "1.2.1.1", Label: "augmentingA", Indexes: []string{"tableDesc"}}}}}},
				},
			},
		},
		// INTEGER indexes fixed.
		{
			in: &Node{Oid: "1", Label: "snSlotsEntry", Indexes: []string{"INTEGER"},
				Children: []*Node{
					{Oid: "1.1", Label: "snSlotsA"}},
			},
			out: &Node{Oid: "1", Label: "snSlotsEntry", Indexes: []string{"snSlotsEntry"},
				Children: []*Node{
					{Oid: "1.1", Label: "snSlotsA", Indexes: []string{"snSlotsEntry"}}},
			},
		},
		// MAC Address type set.
		{
			in:  &Node{Oid: "1", Label: "mac", Hint: "1x:"},
			out: &Node{Oid: "1", Label: "mac", Hint: "1x:", Type: "PhysAddress48"},
		},
	}
	for i, c := range cases {
		// Indexes always end up initilized.
		walkNode(c.out, func(n *Node) {
			if n.Indexes == nil {
				n.Indexes = []string{}
			}
		})

		_ = prepareTree(c.in)

		if !reflect.DeepEqual(c.in, c.out) {
			t.Errorf("prepareTree: difference in case %d", i)
			walkNode(c.in, func(n *Node) {
				t.Errorf("Got: %+v", n)
			})
			walkNode(c.out, func(n *Node) {
				t.Errorf("Wanted: %+v", n)
			})

		}
	}
}
