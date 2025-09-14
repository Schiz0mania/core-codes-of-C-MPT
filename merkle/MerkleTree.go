package merkle

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// MerkleTreeNode 表示Merkle树中的一个节点
type MerkleTreeNode struct {
	Parent *MerkleTreeNode
	Left   *MerkleTreeNode
	Right  *MerkleTreeNode
	Hash   common.Hash
	Tx     *types.Transaction // 使用以太坊的Transaction类型
}

// MerkleTree 表示整个Merkle树结构
type MerkleTree struct {
	Transactions []*types.Transaction // 使用以太坊的Transaction类型
	Nodes        []*MerkleTreeNode
	Root         *MerkleTreeNode
}

// NewMerkleTree 创建并初始化一个新的Merkle树
func NewMerkleTree(transactions []*types.Transaction) *MerkleTree {
	tree := &MerkleTree{
		Transactions: transactions,
	}
	tree.createTree()
	return tree
}

// createTree 构建Merkle树
func (mt *MerkleTree) createTree() time.Duration {
	start := time.Now()

	// 创建叶子节点
	var nodes []*MerkleTreeNode
	for _, tx := range mt.Transactions {
		hash := tx.Hash() // 使用交易的哈希方法
		node := &MerkleTreeNode{Hash: hash, Tx: tx}
		nodes = append(nodes, node)
	}
	mt.Nodes = nodes

	// 构建树结构
	for len(nodes) > 1 {
		var newLevel []*MerkleTreeNode

		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			var right *MerkleTreeNode

			if i+1 < len(nodes) {
				right = nodes[i+1]
			} else {
				// 如果节点数为奇数，复制最后一个节点
				right = &MerkleTreeNode{
					Hash: left.Hash,
					Tx:   left.Tx,
				}
			}

			// 组合左右节点的哈希并计算父节点哈希
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

// computeCombinedHash 计算两个哈希的组合哈希
func (mt *MerkleTree) computeCombinedHash(hash1, hash2 common.Hash) common.Hash {
	// 将两个哈希值拼接后计算哈希
	data := append(hash1.Bytes(), hash2.Bytes()...)
	return crypto.Keccak256Hash(data)
}

// GetRequiredHashes 获取验证指定交易所需的哈希值数量
func (mt *MerkleTree) GetRequiredHashes(transactions []*types.Transaction) int {
	if len(transactions) == 0 {
		return 0
	}

	// 将目标交易转换为哈希集合
	targetHashes := make(map[common.Hash]bool)
	for _, tx := range transactions {
		targetHashes[tx.Hash()] = true
	}

	_, needs := mt.calculateRequiredHashes(mt.Root, targetHashes)
	return needs
}

// calculateRequiredHashes 递归计算所需的哈希值
func (mt *MerkleTree) calculateRequiredHashes(node *MerkleTreeNode, targetHashes map[common.Hash]bool) (bool, int) {
	if node == nil {
		return false, 0
	}

	// 如果是叶子节点，检查是否在目标集合中
	if node.Left == nil && node.Right == nil {
		if _, exists := targetHashes[node.Hash]; exists {
			return true, 0
		}
		return false, 0
	}

	leftFound, leftNeeds := mt.calculateRequiredHashes(node.Left, targetHashes)
	rightFound, rightNeeds := mt.calculateRequiredHashes(node.Right, targetHashes)

	if leftFound && rightFound {
		// 如果左右子树都包含目标，需要左右子树所需的哈希之和
		return true, leftNeeds + rightNeeds
	} else if leftFound {
		// 如果只有左子树包含目标，需要左子树所需的哈希加上右子树的哈希
		return true, leftNeeds + 1
	} else if rightFound {
		// 如果只有右子树包含目标，需要右子树所需的哈希加上左子树的哈希
		return true, rightNeeds + 1
	}

	// 如果都不包含目标，返回false
	return false, 0
}

// GetProof 获取特定交易的Merkle证明
func (mt *MerkleTree) GetProof(tx *types.Transaction) []common.Hash {
	var proof []common.Hash
	txHash := tx.Hash()
	node := mt.findLeafNode(txHash)

	for node != nil && node.Parent != nil {
		parent := node.Parent
		if parent.Left == node {
			proof = append(proof, parent.Right.Hash)
		} else {
			proof = append(proof, parent.Left.Hash)
		}
		node = parent
	}

	return proof
}

// findLeafNode 查找包含特定交易哈希的叶子节点
func (mt *MerkleTree) findLeafNode(txHash common.Hash) *MerkleTreeNode {
	for _, node := range mt.Nodes {
		if node.Hash == txHash {
			return node
		}
	}
	return nil
}

// VerifyProof 验证Merkle证明
func (mt *MerkleTree) VerifyProof(tx *types.Transaction, proof []common.Hash) bool {
	hash := tx.Hash()

	for _, proofHash := range proof {
		hash = mt.computeCombinedHash(hash, proofHash)
	}

	return hash == mt.Root.Hash
}
