package verkle

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// VerkleTree represents a Verkle tree structure with branching factor K=16
const K int = 16

// Node represents a node in the Verkle tree
type Node struct {
	Children    []*Node            // Child nodes (up to K children)
	IsLeaf      bool               // Flag indicating if this is a leaf node
	TxHash      common.Hash        // Transaction hash (only for leaf nodes)
	Hash        common.Hash        // Hash value of this node
	Parent      *Node              // Reference to parent node
	Transaction *types.Transaction // Ethereum transaction (only for leaf nodes)
}

// VerkleTree represents the complete Verkle tree structure
type VerkleTree struct {
	Root *Node // Root node of the tree
	K    int   // Branching factor (arity) of the tree
}

// NewVerkleTreeFromTransactions creates a new Verkle tree from a list of transactions
func NewVerkleTreeFromTransactions(txs []*types.Transaction) *VerkleTree {

	t := &VerkleTree{K: K}
	if len(txs) == 0 {
		return t
	}

	// Create leaf nodes from transactions
	currentLevel := make([]*Node, len(txs))
	for i, tx := range txs {
		currentLevel[i] = &Node{
			IsLeaf:      true,
			TxHash:      tx.Hash(),
			Transaction: tx,
		}
	}

	// Build tree structure from bottom up
	for len(currentLevel) > 1 {
		var nextLevel []*Node
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

	t.Root = currentLevel[0]
	t.ComputeHashes()
	return t
}

// ComputeHashes calculates and sets the hash values for all nodes in the tree
func (t *VerkleTree) ComputeHashes() {
	if t == nil || t.Root == nil {
		return
	}
	computeHashesPostOrder_vk(t.Root)
}

// computeHashesPostOrder_vk recursively computes node hashes using a post-order traversal
func computeHashesPostOrder_vk(node *Node) common.Hash {
	if node == nil {
		return common.Hash{}
	}

	// Leaf node: hash is the transaction hash itself
	if node.IsLeaf {
		if node.Hash == (common.Hash{}) {
			node.Hash = node.TxHash
		}
		return node.Hash
	}

	// Internal node: concatenate child hashes and hash the result
	buf := make([]byte, 0, len(node.Children)*common.HashLength)
	for _, child := range node.Children {
		childHash := computeHashesPostOrder_vk(child)
		buf = append(buf, childHash.Bytes()...)
	}
	node.Hash = crypto.Keccak256Hash(buf)
	return node.Hash
}

// GetRequiredHashes calculates the number of additional hashes needed to verify specified target hashes
func (t *VerkleTree) GetRequiredHashes(targets []common.Hash) int {
	if t == nil || t.Root == nil || len(targets) == 0 {
		return 0
	}

	// Convert target hashes to a set for efficient lookup
	set := make(map[common.Hash]struct{}, len(targets))
	for _, h := range targets {
		set[h] = struct{}{}
	}

	// Calculate required hashes
	flag, needs := calculateRequiredHashes_vk(t.Root, set)
	if flag {
		return needs
	}
	return 0
}

// GetRequiredHashesForTxs calculates required hashes for a list of target transactions
func (t *VerkleTree) GetRequiredHashesForTxs(targetTxs []*types.Transaction) int {
	// Convert transactions to their hashes
	targets := make([]common.Hash, len(targetTxs))
	for i, tx := range targetTxs {
		targets[i] = tx.Hash()
	}

	return t.GetRequiredHashes(targets)
}

// calculateRequiredHashes_vk recursively determines which hashes are needed to verify target hashes
func calculateRequiredHashes_vk(node *Node, targets map[common.Hash]struct{}) (bool, int) {
	if node == nil {
		return false, 0
	}

	// Leaf node: check if it's one of our targets
	if node.IsLeaf {
		_, present := targets[node.TxHash]
		if present {
			return true, 1 // Leaf node returns 1 according to Python version
		}
		return false, 0
	}

	totalNeedSum := 0    // Sum of hashes needed by children that contain targets
	anyTrueFlag := false // Flag if any child contains targets

	// Check all children
	for _, child := range node.Children {
		if child == nil {
			continue
		}
		flag, need := calculateRequiredHashes_vk(child, targets)
		if flag {
			anyTrueFlag = true
			totalNeedSum += need
		}
	}

	// If any child contains targets, we need to include this node's hash
	if anyTrueFlag {
		return true, totalNeedSum + 1
	}
	return false, 0
}

// isTransactionEqual compares two transactions for equality
func isTransactionEqual(tx1, tx2 *types.Transaction) bool {
	if tx1 == nil || tx2 == nil {
		return tx1 == tx2
	}
	return tx1.Hash() == tx2.Hash()
}
