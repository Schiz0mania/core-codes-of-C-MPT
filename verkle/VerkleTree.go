// package verkle
//
// import (
//
//	"log"
//	"time"
//
//	"github.com/ethereum/go-ethereum/common"
//	"github.com/ethereum/go-ethereum/core/types"
//	"github.com/ethereum/go-ethereum/crypto"
//
// )
//
// // VerkleTree 表示一个Verkle树结构 K=16
//
// const K int = 16
//
//	type Node struct {
//		Children []*Node
//		IsLeaf   bool
//		TxHash   common.Hash
//		Hash     common.Hash
//		Parent   *Node
//	}
//
//	type VerkleTree struct {
//		Root *Node
//		K    int
//	}
//
// // NewVerkleTreeFromTransactions 从交易列表创建Verkle树
//
//	func NewVerkleTreeFromTransactions(txs []*types.Transaction) *VerkleTree {
//		start := time.Now()
//		defer func() {
//			elapsed := time.Since(start)
//			log.Printf("Verkle树构建耗时: %v", elapsed)
//		}()
//
//		leafHashes := make([]common.Hash, len(txs))
//		for i, tx := range txs {
//			leafHashes[i] = tx.Hash()
//		}
//		return NewVerkleTreeFromHashes(leafHashes)
//	}
//
// // NewVerkleTreeFromHashes 从哈希列表创建Verkle树
//
//	func NewVerkleTreeFromHashes(leafHashes []common.Hash) *VerkleTree {
//		t := &VerkleTree{K: K}
//		if len(leafHashes) == 0 {
//			return t
//		}
//
//		currentLevel := make([]*Node, len(leafHashes))
//		for i := range leafHashes {
//			currentLevel[i] = &Node{IsLeaf: true, TxHash: leafHashes[i]}
//		}
//
//		for len(currentLevel) > 1 {
//			var nextLevel []*Node
//			for i := 0; i < len(currentLevel); i += t.K {
//				end := i + t.K
//				if end > len(currentLevel) {
//					end = len(currentLevel)
//				}
//				children := currentLevel[i:end]
//				parent := &Node{Children: make([]*Node, len(children))}
//				copy(parent.Children, children)
//				for _, child := range children {
//					child.Parent = parent
//				}
//				nextLevel = append(nextLevel, parent)
//			}
//			currentLevel = nextLevel
//		}
//
//		t.Root = currentLevel[0]
//		t.ComputeHashes()
//		return t
//	}
//
// // ComputeHashes 计算树中所有节点的哈希值
//
//	func (t *VerkleTree) ComputeHashes() {
//		if t == nil || t.Root == nil {
//			return
//		}
//		computeHashesPostOrder_vk(t.Root)
//	}
//
// // computeHashesPostOrder_vk 后序遍历计算节点哈希
//
//	func computeHashesPostOrder_vk(node *Node) common.Hash {
//		if node == nil {
//			return common.Hash{}
//		}
//		if node.IsLeaf {
//			node.Hash = node.TxHash
//			return node.Hash
//		}
//
//		buf := make([]byte, 0, len(node.Children)*common.HashLength)
//		for _, child := range node.Children {
//			childHash := computeHashesPostOrder_vk(child)
//			buf = append(buf, childHash.Bytes()...)
//		}
//		node.Hash = crypto.Keccak256Hash(buf)
//		return node.Hash
//	}
//
// // GetRequiredHashes 获取验证指定交易所需的哈希值数量
//
//	func (t *VerkleTree) GetRequiredHashes(targets []common.Hash) int {
//		if t == nil || t.Root == nil || len(targets) == 0 {
//			return 0
//		}
//		set := make(map[common.Hash]struct{}, len(targets))
//		for _, h := range targets {
//			set[h] = struct{}{}
//		}
//		flag, needs := calculateRequiredHashes_vk(t.Root, set)
//		if flag {
//			return needs
//		}
//		return 0
//	}
//
// // GetRequiredHashesForTxs 获取验证指定交易所需的哈希值数量（交易对象版本）
//
//	func (t *VerkleTree) GetRequiredHashesForTxs(targetTxs []*types.Transaction) int {
//		targets := make([]common.Hash, len(targetTxs))
//		for i, tx := range targetTxs {
//			targets[i] = tx.Hash()
//		}
//		return t.GetRequiredHashes(targets)
//	}
//
// // calculateRequiredHashes_vk 递归计算所需的哈希值
//
//	func calculateRequiredHashes_vk(node *Node, targets map[common.Hash]struct{}) (bool, int) {
//		if node == nil {
//			return false, 0
//		}
//		if node.IsLeaf {
//			_, present := targets[node.TxHash]
//			if present {
//				return true, 0
//			}
//			return false, 0
//		}
//
//		allFalseCount := 0
//		totalNeedSum := 0
//		anyTrueFlag := false
//
//		for _, child := range node.Children {
//			if child == nil {
//				continue
//			}
//			flag, need := calculateRequiredHashes_vk(child, targets)
//			if flag {
//				anyTrueFlag = true
//				totalNeedSum += need
//			} else {
//				allFalseCount++
//			}
//		}
//
//		if anyTrueFlag {
//			return true, totalNeedSum + allFalseCount
//		}
//		return false, 0
//	}
package verkle

import (
	"log"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// VerkleTree 表示一个Verkle树结构 K=16
const K int = 16

type Node struct {
	Children    []*Node
	IsLeaf      bool
	TxHash      common.Hash
	Hash        common.Hash
	Parent      *Node
	Transaction *types.Transaction // 添加交易字段
}

type VerkleTree struct {
	Root *Node
	K    int
}

// NewVerkleTreeFromTransactions 从交易列表创建Verkle树
func NewVerkleTreeFromTransactions(txs []*types.Transaction) *VerkleTree {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		log.Printf("Verkle树构建耗时: %v", elapsed)
	}()

	t := &VerkleTree{K: K}
	if len(txs) == 0 {
		return t
	}

	// 创建叶子节点
	currentLevel := make([]*Node, len(txs))
	for i, tx := range txs {
		currentLevel[i] = &Node{
			IsLeaf:      true,
			TxHash:      tx.Hash(),
			Transaction: tx,
		}
	}

	// 构建树结构
	for len(currentLevel) > 1 {
		var nextLevel []*Node
		for i := 0; i < len(currentLevel); i += t.K {
			end := i + t.K
			if end > len(currentLevel) {
				end = len(currentLevel)
			}
			children := currentLevel[i:end]
			parent := &Node{Children: make([]*Node, len(children))}
			copy(parent.Children, children)
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

// ComputeHashes 计算树中所有节点的哈希值
func (t *VerkleTree) ComputeHashes() {
	if t == nil || t.Root == nil {
		return
	}
	computeHashesPostOrder_vk(t.Root)
}

// computeHashesPostOrder_vk 后序遍历计算节点哈希
func computeHashesPostOrder_vk(node *Node) common.Hash {
	if node == nil {
		return common.Hash{}
	}
	if node.IsLeaf {
		if node.Hash == (common.Hash{}) {
			node.Hash = node.TxHash
		}
		return node.Hash
	}

	buf := make([]byte, 0, len(node.Children)*common.HashLength)
	for _, child := range node.Children {
		childHash := computeHashesPostOrder_vk(child)
		buf = append(buf, childHash.Bytes()...)
	}
	node.Hash = crypto.Keccak256Hash(buf)
	return node.Hash
}

// GetRequiredHashes 获取验证指定交易所需的哈希值数量
func (t *VerkleTree) GetRequiredHashes(targets []common.Hash) int {
	if t == nil || t.Root == nil || len(targets) == 0 {
		return 0
	}
	set := make(map[common.Hash]struct{}, len(targets))
	for _, h := range targets {
		set[h] = struct{}{}
	}
	flag, needs := calculateRequiredHashes_vk(t.Root, set)
	if flag {
		return needs
	}
	return 0
}

// GetRequiredHashesForTxs 获取验证指定交易所需的哈希值数量（交易对象版本）
func (t *VerkleTree) GetRequiredHashesForTxs(targetTxs []*types.Transaction) int {
	targets := make([]common.Hash, len(targetTxs))
	for i, tx := range targetTxs {
		targets[i] = tx.Hash()
	}
	return t.GetRequiredHashes(targets)
}

// calculateRequiredHashes_vk 递归计算所需的哈希值

func calculateRequiredHashes_vk(node *Node, targets map[common.Hash]struct{}) (bool, int) {
	if node == nil {
		return false, 0
	}

	// 如果是叶子节点
	if node.IsLeaf {
		_, present := targets[node.TxHash]
		if present {
			return true, 1 // 根据Python版本，叶子节点返回1
		}
		return false, 0
	}

	totalNeedSum := 0
	anyTrueFlag := false

	// 遍历所有子节点
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

	if anyTrueFlag {
		
		return true, totalNeedSum + 1
	}
	return false, 0
}

// 辅助函数：比较两个交易是否相等
func isTransactionEqual(tx1, tx2 *types.Transaction) bool {
	if tx1 == nil || tx2 == nil {
		return tx1 == tx2
	}
	return tx1.Hash() == tx2.Hash()
}
