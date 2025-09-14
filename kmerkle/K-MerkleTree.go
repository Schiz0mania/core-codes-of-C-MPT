package kmerkle

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// K defines the branching factor (arity) of the Merkle tree
const K int = 16

// Node represents a node in the K-ary Merkle tree
type Node struct {
	Children []*Node     // Child nodes (length between 1 and K)
	IsLeaf   bool        // Flag indicating if this is a leaf node
	TxHash   common.Hash // Transaction hash (only for leaf nodes)
	Hash     common.Hash // Hash value of this node
	Parent   *Node       // Reference to parent node
}

// Tree represents a K-ary Merkle tree structure
type Tree struct {
	Root *Node // Root node of the tree
	K    int   // Branching factor (arity) of the tree
}

// NewFromTransactions creates a new K-ary Merkle tree from a list of transactions
func NewFromTransactions(txs []*types.Transaction) *Tree {
	// Extract transaction hashes
	leafHashes := make([]common.Hash, len(txs))
	for i, tx := range txs {
		leafHashes[i] = tx.Hash()
	}

	// Build tree from the hashes
	return NewFromHashes(leafHashes)
}

// NewFromHashes creates a new K-ary Merkle tree from a list of leaf hashes
func NewFromHashes(leafHashes []common.Hash) *Tree {
	t := &Tree{K: K}
	if len(leafHashes) == 0 {
		return t
	}

	// Create leaf nodes
	currentLevel := make([]*Node, len(leafHashes))
	for i := range leafHashes {
		currentLevel[i] = &Node{IsLeaf: true, TxHash: leafHashes[i]}
	}

	// Build tree levels from bottom up
	for len(currentLevel) > 1 {
		var nextLevel []*Node

		// Group nodes into parent nodes with up to K children
		for i := 0; i < len(currentLevel); i += t.K {
			end := i + t.K
			if end > len(currentLevel) {
				end = len(currentLevel)
			}

			// Create parent node for this group of children
			children := currentLevel[i:end]
			parent := &Node{Children: make([]*Node, len(children))}
			copy(parent.Children, children)

			// Set parent reference for all children
			for _, child := range children {
				child.Parent = parent
			}

			nextLevel = append(nextLevel, parent)
		}
		currentLevel = nextLevel
	}

	// Set the root node
	t.Root = currentLevel[0]

	// Compute hashes for all nodes in the tree
	t.ComputeHashes()
	return t
}

// ComputeHashes calculates and sets the hash values for all nodes in the tree
func (t *Tree) ComputeHashes() {
	if t == nil || t.Root == nil {
		return
	}
	computeHashesPostOrder(t.Root)
}

// computeHashesPostOrder recursively computes node hashes using a post-order traversal
func computeHashesPostOrder(node *Node) common.Hash {
	if node == nil {
		return common.Hash{}
	}

	// Leaf node: hash is the transaction hash itself
	if node.IsLeaf {
		node.Hash = node.TxHash
		return node.Hash
	}

	// Internal node: concatenate child hashes and hash the result
	buf := make([]byte, 0, len(node.Children)*common.HashLength)
	for _, child := range node.Children {
		childHash := computeHashesPostOrder(child)
		buf = append(buf, childHash.Bytes()...)
	}
	node.Hash = crypto.Keccak256Hash(buf)
	return node.Hash
}

// RequiredHashCount calculates the number of additional hashes needed to verify the given target hashes
func (t *Tree) RequiredHashCount(targets []common.Hash) int {
	if t == nil || t.Root == nil || len(targets) == 0 {
		return 0
	}

	// Convert target hashes to a set for efficient lookup
	set := make(map[common.Hash]struct{}, len(targets))
	for _, h := range targets {
		set[h] = struct{}{}
	}

	// Calculate required hashes
	flag, needs := calculateRequiredHashes(t.Root, set)
	if flag {
		return needs
	}
	return 0
}

// RequiredHashCountForTxs calculates required hashes for a list of target transactions
func (t *Tree) RequiredHashCountForTxs(targetTxs []*types.Transaction) int {
	// Convert transactions to their hashes
	targets := make([]common.Hash, len(targetTxs))
	for i, tx := range targetTxs {
		targets[i] = tx.Hash()
	}

	return t.RequiredHashCount(targets)
}

// calculateRequiredHashes recursively determines which hashes are needed to verify target hashes
func calculateRequiredHashes(node *Node, targets map[common.Hash]struct{}) (bool, int) {
	if node == nil {
		return false, 0
	}

	// Leaf node: check if it's one of our targets
	if node.IsLeaf {
		_, present := targets[node.TxHash]
		if present {
			return true, 0
		}
		return false, 0
	}

	// Internal node: check all children
	allFalseCount := 0   // Count of children that don't contain any targets
	totalNeedSum := 0    // Sum of hashes needed by children that do contain targets
	anyTrueFlag := false // Flag if any child contains targets

	for _, child := range node.Children {
		if child == nil {
			continue
		}
		flag, need := calculateRequiredHashes(child, targets)
		if flag {
			anyTrueFlag = true
			totalNeedSum += need
		} else {
			allFalseCount++
		}
	}

	// If any child contains targets, we need to include hashes of non-target children
	if anyTrueFlag {
		return true, totalNeedSum + allFalseCount
	}
	return false, 0
}
