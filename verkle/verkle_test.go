//package mytree
//
//import (
//	"math/big"
//	"testing"
//
//	"github.com/ethereum/go-ethereum/common"
//	"github.com/ethereum/go-ethereum/core/types"
//)
//
//// TestGetRequiredHashesForTxs 测试 GetRequiredHashesForTxs 方法
//func TestGetRequiredHashesForTxs(t *testing.T) {
//	// 创建一些测试交易
//	var transactions []*types.Transaction
//	for i := 0; i < 1000; i++ {
//		tx := types.NewTransaction(
//			uint64(i),                 // nonce
//			common.Address{},          // to
//			big.NewInt(int64(i*1000)), // value
//			21000,                     // gas limit
//			big.NewInt(1),             // gas price
//			[]byte("test data"),       // data
//		)
//		transactions = append(transactions, tx)
//	}
//
//	// 从交易创建 Verkle 树
//	tree := NewVerkleTreeFromTransactions(transactions)
//	if tree == nil || tree.Root == nil {
//		t.Fatal("Failed to create Verkle tree")
//	}
//
//	//随机两个
//	targetTxs := []*types.Transaction{transactions[0], transactions[123]}
//
//	// 计算所需哈希数量
//	requiredHashes := tree.GetRequiredHashesForTxs(targetTxs)
//
//	// 验证结果不为负数
//	if requiredHashes < 0 {
//		t.Errorf("Expected non-negative required hashes, got %d", requiredHashes)
//	}
//
//	t.Logf("Required hashes for %d target transactions: %d", len(targetTxs), requiredHashes)
//}

package verkle

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

// testKey is a pre-generated private key for signing
var testKey, _ = crypto.GenerateKey()

// newTestTx creates a dummy signed transaction
func newTestTx(signer types.Signer, nonce uint64, amount int64) *types.Transaction {
	// Generate a random 20-byte address
	addrBytes := make([]byte, 20)
	if _, err := rand.Read(addrBytes); err != nil {
		panic(err)
	}
	addr := common.BytesToAddress(addrBytes)

	// Ensure hash uniqueness by modifying the last two bytes of the address
	addrBytes = addr.Bytes()
	addrBytes[19] = byte(nonce % 256)
	addrBytes[18] = byte((nonce >> 8) % 256)
	addr = common.BytesToAddress(addrBytes)

	tx := types.NewTransaction(nonce, addr, big.NewInt(amount), 21000, big.NewInt(100), nil)
	signedTx, err := types.SignTx(tx, signer, testKey)
	if err != nil {
		panic(err)
	}
	return signedTx
}

// TestGetRequiredHashesForTxs_verkle tests the scenario with multiple clusters
func TestGetRequiredHashesForTxs_verkle(t *testing.T) {
	// 1. Setup environment
	signer := types.LatestSigner(params.TestChainConfig)
	const totalTxCount = 5000
	const clusterCount = 256

	// 2. Generate 1000 transactions and randomly distribute them into 32 clusters
	t.Logf("Generating %d transactions and randomly distributing them into %d clusters...", totalTxCount, clusterCount)
	allTxs := make([]*types.Transaction, totalTxCount)
	clusters := make(map[int][]*types.Transaction)

	// Initialize random number generator
	rand.Seed(time.Now().UnixNano())

	// Initialize all clusters
	for i := 0; i < clusterCount; i++ {
		clusters[i] = make([]*types.Transaction, 0)
	}

	// Randomly assign transactions to clusters
	for i := 0; i < totalTxCount; i++ {
		tx := newTestTx(signer, uint64(i), 100)
		allTxs[i] = tx

		// Randomly select a cluster
		clusterID := rand.Intn(clusterCount)
		clusters[clusterID] = append(clusters[clusterID], tx)
	}

	// 3. Build Verkle tree with all 1000 transactions
	t.Log("Building Verkle tree with all transactions...")
	startTime := time.Now()
	tree := NewVerkleTreeFromTransactions(allTxs)
	buildDuration := time.Since(startTime)
	t.Logf("Verkle tree built, time taken: %v", buildDuration)
	t.Logf("Tree root hash: %s", tree.Root.Hash.Hex())

	// 4. Define test cases (based on requested number of clusters)
	testCases := []struct {
		name              string
		clustersToRequest int // Number of clusters to request transactions from
	}{
		{"Requesting txs from 1 cluster", 0},
		{"Requesting txs from 1 cluster", 1},
		{"Requesting txs from 2 clusters", 2},
		{"Requesting txs from 4 clusters", 4},
		{"Requesting txs from 8 clusters", 8},
		{"Requesting txs from 16 clusters", 16},
		{"Requesting txs from 32 clusters", 32},
	}

	// 5. Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Select transactions from the requested number of clusters
			txsToVerify := make([]*types.Transaction, 0)
			selectedClusters := make([]int, 0, tc.clustersToRequest)

			// Randomly select clusters
			for i := 0; i < tc.clustersToRequest; i++ {
				clusterID := rand.Intn(clusterCount)
				// Ensure we don't select the same cluster multiple times
				for contains(selectedClusters, clusterID) {
					clusterID = rand.Intn(clusterCount)
				}
				selectedClusters = append(selectedClusters, clusterID)
				txsToVerify = append(txsToVerify, clusters[clusterID]...)
			}

			txCountInRequest := len(txsToVerify)
			t.Logf("Preparing to verify %d transactions from %d clusters...", txCountInRequest, tc.clustersToRequest)

			// 6. Call GetRequiredHashesForTxs method to calculate required hashes
			startTime := time.Now()
			requiredHashes := tree.GetRequiredHashesForTxs(txsToVerify)
			calcDuration := time.Since(startTime)

			t.Logf(">>> Result: Verifying %d transactions from %d clusters requires %d additional hashes, calculation time: %v",
				txCountInRequest, tc.clustersToRequest, requiredHashes, calcDuration)

			// 7. Assertions and logical validation
			if txCountInRequest > 0 && requiredHashes <= 0 {
				t.Errorf("Error: When verifying partial transactions, required hashes should be greater than 0, got %d", requiredHashes)
			}

			// A looser but absolutely correct assertion is that the number of required hashes
			// should not exceed the total number of transactions.
			if requiredHashes >= totalTxCount {
				t.Errorf("Error: Required hashes (%d) should not be greater than or equal to total transactions (%d)", requiredHashes, totalTxCount)
			}

			// Verify the result is not negative
			if requiredHashes < 0 {
				t.Errorf("Expected non-negative required hashes, got %d", requiredHashes)
			}
		})
	}
}

// Helper function to check if a slice contains a value
func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
