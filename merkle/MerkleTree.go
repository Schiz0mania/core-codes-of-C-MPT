package merkle

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// MerkleTreeNode represents a node in the Merkle tree
type MerkleTreeNode struct {
	Parent *MerkleTreeNode    // Parent node in the tree
	Left   *MerkleTreeNode    // Left child node
	Right  *MerkleTreeNode    // Right child node
	Hash   common.Hash        // Hash value of this node
	Tx     *types.Transaction // Ethereum transaction (only for leaf nodes)
}

// MerkleTree represents the complete Merkle tree structure
type MerkleTree struct {
	Transactions []*types.Transaction // List of transactions in the tree
	Nodes        []*MerkleTreeNode    // All nodes in the tree
	Root         *MerkleTreeNode      // Root node of the tree
}

// NewMerkleTree creates and initializes a new Merkle tree from transactions
func NewMerkleTree(transactions []*types.Transaction) *MerkleTree {
	tree := &MerkleTree{
		Transactions: transactions,
	}
	tree.createTree()
	return tree
}

// createTree constructs the Merkle tree and returns the time taken
func (mt *MerkleTree) createTree() time.Duration {
	start := time.Now()

	// Create leaf nodes from transactions
	var nodes []*MerkleTreeNode
	for _, tx := range mt.Transactions {
		hash := tx.Hash() // Get transaction hash
		node := &MerkleTreeNode{Hash: hash, Tx: tx}
		nodes = append(nodes, node)
	}
	mt.Nodes = nodes

	// Build tree structure from bottom up
	for len(nodes) > 1 {
		var newLevel []*MerkleTreeNode

		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			var right *MerkleTreeNode

			if i+1 < len(nodes) {
				right = nodes[i+1]
			} else {
				// If odd number of nodes, duplicate the last node
				right = &MerkleTreeNode{
					Hash: left.Hash,
					Tx:   left.Tx,
				}
			}

			// Combine left and right hashes to create parent hash
			combinedHash := mt.computeCombinedHash(left.Hash, right.Hash)
			parent := &MerkleTreeNode{
				Left:  left,
				Right: right,
				Hash:  combinedHash,
			}

			left.Parent = parent
			right.Parent = parent
			newLevel = append(newLevel, parent)
		}

		nodes = newLevel
	}

	mt.Root = nodes[0]
	return time.Since(start)
}

// computeCombinedHash computes the hash of two combined hashes
func (mt *MerkleTree) computeCombinedHash(hash1, hash2 common.Hash) common.Hash {
	// Concatenate the two hashes and compute Keccak256 hash
	data := append(hash1.Bytes(), hash2.Bytes()...)
	return crypto.Keccak256Hash(data)
}

// GetRequiredHashes calculates the number of additional hashes needed to verify specified transactions
func (mt *MerkleTree) GetRequiredHashes(transactions []*types.Transaction) int {
	if len(transactions) == 0 {
		return 0
	}

	// Convert target transactions to a set of hashes for efficient lookup
	targetHashes := make(map[common.Hash]bool)
	for _, tx := range transactions {
		targetHashes[tx.Hash()] = true
	}

	_, needs := mt.calculateRequiredHashes(mt.Root, targetHashes)
	return needs
}

// calculateRequiredHashes recursively determines which hashes are needed to verify target hashes
func (mt *MerkleTree) calculateRequiredHashes(node *MerkleTreeNode, targetHashes map[common.Hash]bool) (bool, int) {
	if node == nil {
		return false, 0
	}

	// Leaf node: check if it's one of our targets
	if node.Left == nil && node.Right == nil {
		if _, exists := targetHashes[node.Hash]; exists {
			return true, 0
		}
		return false, 0
	}

	// Check both subtrees
	leftFound, leftNeeds := mt.calculateRequiredHashes(node.Left, targetHashes)
	rightFound, rightNeeds := mt.calculateRequiredHashes(node.Right, targetHashes)

	if leftFound && rightFound {
		// Both subtrees contain targets: sum their needs
		return true, leftNeeds + rightNeeds
	} else if leftFound {
		// Only left subtree contains targets: need left needs plus right subtree's hash
		return true, leftNeeds + 1
	} else if rightFound {
		// Only right subtree contains targets: need right needs plus left subtree's hash
		return true, rightNeeds + 1
	}

	// No targets found in this subtree
	return false, 0
}

// GetProof generates a Merkle proof for a specific transaction
func (mt *MerkleTree) GetProof(tx *types.Transaction) []common.Hash {
	var proof []common.Hash
	txHash := tx.Hash()
	node := mt.findLeafNode(txHash)

	// Traverse up the tree to collect proof hashes
	for node != nil && node.Parent != nil {
		parent := node.Parent
		if parent.Left == node {
			// If current node is left child, add right sibling to proof
			proof = append(proof, parent.Right.Hash)
		} else {
			// If current node is right child, add left sibling to proof
			proof = append(proof, parent.Left.Hash)
		}
		node = parent
	}

	return proof
}

// findLeafNode locates the leaf node containing a specific transaction hash
func (mt *MerkleTree) findLeafNode(txHash common.Hash) *MerkleTreeNode {
	for _, node := range mt.Nodes {
		if node.Hash == txHash {
			return node
		}
	}
	return nil
}

// VerifyProof verifies a Merkle proof for a transaction
func (mt *MerkleTree) VerifyProof(tx *types.Transaction, proof []common.Hash) bool {
	hash := tx.Hash()

	// Recompute the root hash using the proof
	for _, proofHash := range proof {
		hash = mt.computeCombinedHash(hash, proofHash)
	}

	// Check if the computed root matches the actual root
	return hash == mt.Root.Hash
}
