package cmpt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// TrieNode interface defines basic operations for MPT nodes
type TrieNode interface {
	GetPath() []byte
	SetPath(path []byte)
	GetHash() common.Hash
}

// FullNode represents a full MPT node with 16 children branches and one value node
type FullNode struct {
	Path     []byte
	Children [17]TrieNode // 0-15: hex characters, 16: value node
	Flags    interface{}
	HashVal  common.Hash
}

func (f *FullNode) GetPath() []byte      { return f.Path }
func (f *FullNode) SetPath(path []byte)  { f.Path = path }
func (f *FullNode) GetHash() common.Hash { return f.HashVal }

// ShortNode represents a shortcut node that compresses multiple nodes
type ShortNode struct {
	Path    []byte
	Key     []byte
	Val     TrieNode
	Flags   interface{}
	HashVal common.Hash
}

func (s *ShortNode) GetPath() []byte      { return s.Path }
func (s *ShortNode) SetPath(path []byte)  { s.Path = path }
func (s *ShortNode) GetHash() common.Hash { return s.HashVal }

// HashNode represents a leaf node containing hashed data
type HashNode struct {
	Pre   []byte
	Key   []byte
	Value []byte
	Hash  common.Hash
	Path  []byte
}

func (h *HashNode) GetPath() []byte      { return h.Path }
func (h *HashNode) SetPath(path []byte)  { h.Path = path }
func (h *HashNode) GetHash() common.Hash { return h.Hash }

// Trie represents the Merkle Patricia Trie structure
type Trie struct {
	Root TrieNode
}

func NewTrie() *Trie {
	return &Trie{}
}

// keyToNibbles converts a byte slice to its nibble representation
func keyToNibbles(key []byte) []byte {
	nibbles := make([]byte, len(key)*2)
	for i, b := range key {
		nibbles[i*2] = b >> 4
		nibbles[i*2+1] = b & 0x0F
	}
	return nibbles
}

// nibblesToKey converts nibbles back to a byte slice
func nibblesToKey(nibbles []byte) []byte {
	if len(nibbles)%2 != 0 {
		nibbles = append(nibbles, 0)
	}
	key := make([]byte, len(nibbles)/2)
	for i := 0; i < len(key); i++ {
		key[i] = (nibbles[i*2] << 4) | nibbles[i*2+1]
	}
	return key
}

// Insert adds a key-value pair to the trie
func (t *Trie) Insert(key, value []byte) error {
	if len(key) == 0 {
		return errors.New("key cannot be empty")
	}
	nibbles := keyToNibbles(key)
	dirty, newNode, err := t.insert(t.Root, []byte{}, nibbles, value)
	if err != nil {
		return err
	}
	if dirty {
		t.Root = newNode
	}
	return nil
}

// insert recursively inserts a key-value pair into the trie
func (t *Trie) insert(n TrieNode, path, key []byte, value []byte) (bool, TrieNode, error) {
	if n == nil {
		return true, &HashNode{
			Pre:   key,
			Key:   nibblesToKey(append(path, key...)),
			Value: value,
			Path:  nibblesToKey(append(path, key...)),
		}, nil
	}

	switch node := n.(type) {
	case *ShortNode:
		nodeKeyNibbles := keyToNibbles(node.Key)
		matchlen := prefixLen(key, nodeKeyNibbles)

		switch {
		case matchlen == len(nodeKeyNibbles):
			newPath := append(path, nodeKeyNibbles...)
			dirty, nn, err := t.insert(node.Val, newPath, key[matchlen:], value)
			if err != nil {
				return false, n, err
			}
			if !dirty {
				return false, n, nil
			}
			return true, &ShortNode{
				Path:  nibblesToKey(newPath),
				Key:   node.Key,
				Val:   nn,
				Flags: t.newFlag(),
			}, nil

		case matchlen == len(key):
			branch := &FullNode{}
			branch.Children[16] = &HashNode{Value: value}
			branch.Path = nibblesToKey(append(path, key...))
			if matchlen < len(nodeKeyNibbles) && int(nodeKeyNibbles[matchlen]) < 16 {
				branch.Children[nodeKeyNibbles[matchlen]] = node
			} else {
				return false, nil, fmt.Errorf("invalid nibble value or index out of range")
			}
			node.Path = nibblesToKey(append(path, key...))
			node.Key = nibblesToKey(nodeKeyNibbles[matchlen:])
			return true, &ShortNode{
				Path:  nibblesToKey(path),
				Key:   nibblesToKey(key),
				Val:   branch,
				Flags: t.newFlag(),
			}, nil

		case matchlen == 0:
			branch := &FullNode{}
			leaf := &HashNode{
				Path:  nibblesToKey(append(path, key...)),
				Value: value,
				Pre:   key,
			}
			branch.Path = nibblesToKey(path)
			if len(nodeKeyNibbles) > 0 && int(nodeKeyNibbles[0]) < 16 {
				branch.Children[nodeKeyNibbles[0]] = node
			} else {
				return false, nil, fmt.Errorf("invalid nibble value or index out of range")
			}
			if len(key) > 0 && int(key[0]) < 16 {
				branch.Children[key[0]] = leaf
			} else {
				return false, nil, fmt.Errorf("invalid nibble value or index out of range")
			}
			return true, branch, nil

		default:
			branch := &FullNode{}
			branch.Path = nibblesToKey(append(path, key[:matchlen]...))
			if matchlen < len(nodeKeyNibbles) && int(nodeKeyNibbles[matchlen]) < 16 {
				branch.Children[nodeKeyNibbles[matchlen]] = node
			} else {
				return false, nil, fmt.Errorf("invalid nibble value or index out of range")
			}
			leaf := &HashNode{
				Path:  nibblesToKey(append(path, key[:matchlen]...)),
				Value: value,
				Pre:   key[matchlen:],
			}
			if matchlen < len(key) && int(key[matchlen]) < 16 {
				branch.Children[key[matchlen]] = leaf
			} else {
				return false, nil, fmt.Errorf("invalid nibble value or index out of range")
			}
			node.Key = nibblesToKey(nodeKeyNibbles[matchlen:])
			return true, &ShortNode{
				Path:  nibblesToKey(path),
				Key:   nibblesToKey(key[:matchlen]),
				Val:   branch,
				Flags: t.newFlag(),
			}, nil
		}

	case *FullNode:
		if len(key) == 0 {
			return false, n, errors.New("empty key")
		}
		if int(key[0]) >= 16 {
			return false, n, fmt.Errorf("invalid nibble value: %d", key[0])
		}
		dirty, nn, err := t.insert(node.Children[key[0]], append(path, key[0]), key[1:], value)
		if err != nil || !dirty {
			return false, n, err
		}
		newNode := &FullNode{
			Path:  node.Path,
			Flags: t.newFlag(),
		}
		copy(newNode.Children[:], node.Children[:])
		newNode.Children[key[0]] = nn
		return true, newNode, nil

	case *HashNode:
		rn, err := t.resolveAndTrack(node, key, path)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.insert(rn, path, key, value)
		if err != nil || !dirty {
			return false, rn, err
		}
		return true, nn, nil

	default:
		return false, nil, errors.New("invalid node type")
	}
}

// prefixLen returns the length of the common prefix between two byte slices
func prefixLen(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return minLen
}

// resolveAndTrack processes HashNode during insertion
func (t *Trie) resolveAndTrack(n *HashNode, key2, path []byte) (TrieNode, error) {
	l := prefixLen(n.Pre, key2)
	switch {
	case l == len(n.Pre):
		if bytes.Equal(n.Pre, key2) {
			return nil, errors.New("node exists")
		}
		f := &FullNode{}
		f.Path = nibblesToKey(path)
		f.Children[16] = &HashNode{Value: n.Value}
		return f, nil
	case l != 0:
		s := &ShortNode{
			Path: nibblesToKey(path),
			Key:  nibblesToKey(key2[:l]),
			Val:  n,
		}
		n.Pre = n.Pre[l:]
		return s, nil
	default:
		f := &FullNode{}
		f.Path = nibblesToKey(path)
		if len(n.Pre) > 0 && int(n.Pre[0]) < 16 {
			f.Children[n.Pre[0]] = n
		} else {
			f.Children[16] = n
		}
		return f, nil
	}
}

// fixedPath recursively updates node paths after insertion
func (t *Trie) fixedPath(node TrieNode, path []byte) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *HashNode:
		n.Path = n.Key
	case *ShortNode:
		n.Path = nibblesToKey(path)
		if n.Val != nil {
			t.fixedPath(n.Val, append(path, keyToNibbles(n.Key)...))
		}
	case *FullNode:
		n.Path = nibblesToKey(path)
		for i := 0; i < 16; i++ {
			if n.Children[i] != nil {
				t.fixedPath(n.Children[i], append(path, byte(i)))
			}
		}
	}
}

// newFlag creates a new flag for node (placeholder for future use)
func (t *Trie) newFlag() interface{} { return nil }

// CalculateRequiredHashes2 computes the number of required hashes for given cluster keys
func (t *Trie) CalculateRequiredHashes2(clusterKeys [][]byte) int {
	if t.Root == nil || len(clusterKeys) == 0 {
		return 0
	}
	flags, needs := t.calculateHashes(t.Root, clusterKeys)
	if flags {
		return needs
	}
	return 0
}

// calculateHashes recursively determines if nodes require hashing
func (t *Trie) calculateHashes(node TrieNode, clusterKeys [][]byte) (bool, int) {
	if node == nil {
		return false, 0
	}
	if hashNode, ok := node.(*HashNode); ok {
		nodeKey := keyToNibbles(hashNode.Key)
		for _, clusterKey := range clusterKeys {
			if bytes.Equal(nodeKey, clusterKey) {
				return true, 0
			}
		}
		return false, 0
	}
	if shortNode, ok := node.(*ShortNode); ok {
		return t.calculateHashes(shortNode.Val, clusterKeys)
	}
	if fullNode, ok := node.(*FullNode); ok {
		allFalseCount := 0
		totalNeedSum := 0
		anyTrueFlag := false
		for i := 0; i < 16; i++ {
			if fullNode.Children[i] == nil {
				continue
			}
			flag, need := t.calculateHashes(fullNode.Children[i], clusterKeys)
			if flag {
				anyTrueFlag = true
				totalNeedSum += need
			} else {
				allFalseCount++
			}
		}
		if anyTrueFlag {
			return true, totalNeedSum + allFalseCount
		}
	}
	return false, 0
}

// BuildCMPTTree constructs a CMPT from transaction clusters
func BuildCMPTTree(trie *Trie, clusters map[string][]*types.Transaction) (*Trie, time.Duration) {
	startTime := time.Now()

	for prefixStr, txsInCluster := range clusters {
		prefix := []byte(prefixStr)

		// Pack all transactions in a cluster into a single value
		var clusterValue []byte
		for _, tx := range txsInCluster {
			txData, _ := tx.MarshalBinary()
			clusterValue = append(clusterValue, txData...)
		}

		// Insert using prefix as key and packed data as value
		if err := trie.Insert(prefix, clusterValue); err != nil {
			fmt.Printf("Failed to insert cluster: %v\n", err)
			continue
		}
	}

	trie.fixedPath(trie.Root, []byte{})
	trie.ComputeHash(trie.Root)
	return trie, time.Since(startTime)
}

// ComputeHash recursively computes hashes for all nodes in the trie
func (t *Trie) ComputeHash(node TrieNode) common.Hash {
	if node == nil {
		return common.Hash{}
	}
	switch n := node.(type) {
	case *HashNode:
		if n.Hash != (common.Hash{}) {
			return n.Hash
		}
		data := append(n.Pre, n.Value...)
		n.Hash = crypto.Keccak256Hash(data)
		return n.Hash
	case *ShortNode:
		childHash := t.ComputeHash(n.Val)
		data := append(keyToNibbles(n.Key), childHash.Bytes()...)
		n.HashVal = crypto.Keccak256Hash(data)
		return crypto.Keccak256Hash(data)
	case *FullNode:
		var data []byte
		for i, child := range n.Children {
			if child != nil {
				childHash := t.ComputeHash(child)
				data = append(data, byte(i))
				data = append(data, childHash.Bytes()...)
			}
		}
		n.HashVal = crypto.Keccak256Hash(data)
		return n.HashVal
	default:
		return common.Hash{}
	}
}

// PrintTrie recursively prints the trie structure for debugging
func (t *Trie) PrintTrie(node TrieNode, indent string) {
	if node == nil {
		fmt.Println(indent + "nil")
		return
	}
	switch n := node.(type) {
	case *HashNode:
		fmt.Printf("%sHashNode: Key=%s, Value=%s\n", indent, hex.EncodeToString(n.Key), hex.EncodeToString(n.Value))
	case *ShortNode:
		fmt.Printf("%sShortNode: Key=%s\n", indent, hex.EncodeToString(n.Key))
		t.PrintTrie(n.Val, indent+"  ")
	case *FullNode:
		fmt.Printf("%sFullNode: Path=%s\n", indent, hex.EncodeToString(n.Path))
		for i, child := range n.Children {
			if child != nil {
				fmt.Printf("%s  Child[%d]:\n", indent, i)
				t.PrintTrie(child, indent+"    ")
			}
		}
	}
}
