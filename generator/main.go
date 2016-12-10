package main

import "fmt"
import "strings"

// Helper to walk MIB nodes.
func walkNode(n *Node, f func(n *Node)) {
	f(n)
	for _, c := range n.Children {
		walkNode(c, f)
	}
}

// Transform the tree
func prepareTree(nodes *Node) map[string]*Node {
	// Build a map from names and oids to nodes.
	nameToNode := map[string]*Node{}
	walkNode(nodes, func(n *Node) {
		nameToNode[n.Oid] = n
		nameToNode[n.Label] = n
	})

	// Trim down description to first sentance, removing extra whitespace.
	walkNode(nodes, func(n *Node) {
		s := strings.Join(strings.Fields(n.Description), " ")
		n.Description = strings.Split(s, ". ")[0]
	})

	// Copy over indexes based on augments.
	walkNode(nodes, func(n *Node) {
		if n.Augments == "" {
			return
		}
		augmented := nameToNode[n.Augments]
		for _, c := range n.Children {
			c.Indexes = augmented.Indexes
		}
		n.Indexes = augmented.Indexes
	})

	return nameToNode
}

func main() {
	nodes := getMIBTree()
	nameToNode := prepareTree(nodes)

	_ = nameToNode

	walkNode(nodes, func(n *Node) {
		fmt.Printf("%s %s %s %s %s\n", n.Oid, n.Label, n.Type, n.Indexes, n.Description)
	})
}
