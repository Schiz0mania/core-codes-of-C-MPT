// package merkle
//
// import (
//
//	"github.com/ethereum/go-ethereum/common"
//	"github.com/ethereum/go-ethereum/core/types"
//	"github.com/ethereum/go-ethereum/crypto"
//	"github.com/ethereum/go-ethereum/params"
//	"math/big"
//	"math/rand"
//	"testing"
//	"time"
//
// )
//
// // testKey 预先生成一个用于签名的私钥
// var testKey, _ = crypto.GenerateKey()
//
// // newTestTx 创建一个带签名的虚拟交易
//
//	func newTestTx(signer types.Signer, nonce uint64, amount int64) *types.Transaction {
//		addr := common.HexToAddress("0x0000000000000000000000000000000000000000")
//		// 通过改变 nonce 和 to 地址来确保交易哈希的唯一性
//		addr[19] = byte(nonce % 256)
//		addr[18] = byte((nonce >> 8) % 256)
//
//		tx := types.NewTransaction(nonce, addr, big.NewInt(amount), 21000, big.NewInt(100), nil)
//		signedTx, err := types.SignTx(tx, signer, testKey)
//		if err != nil {
//			panic(err)
//		}
//		return signedTx
//	}
//
//	func TestMPTTree_GetRequiredHashes_OneClass(t *testing.T) {
//		// 1. 设置环境
//		signer := types.LatestSigner(params.TestChainConfig)
//		const totalTxCount = 1000
//		const clusterCount = 32
//
//		// 2. 生成 1000 个交易，并按逻辑分为 32 类
//		t.Logf("正在生成 %d 个交易...", totalTxCount)
//		allTxs := make([]*types.Transaction, totalTxCount)
//		// 使用 map 来按逻辑对交易进行分组
//		// Key: clusterID (0-31), Value: 该类别的交易列表
//		clusters := make(map[int][]*types.Transaction)
//
//		for i := 0; i < totalTxCount; i++ {
//			tx := newTestTx(signer, uint64(i), 100)
//			allTxs[i] = tx // 按顺序存入总列表
//
//			clusterID := rand.Intn(clusterCount)
//			clusters[clusterID] = append(clusters[clusterID], tx)
//		}
//
//		// 3. 使用所有 1000 个交易构建 MPT 树
//		t.Log("正在用全部交易构建 MPT 树...")
//		trie := NewTrie()
//		startTime := time.Now()
//		BuildMPTTree(trie, allTxs)
//		buildDuration := time.Since(startTime)
//		t.Logf("MPT 树构建完成，耗时: %v", buildDuration)
//
//		// 4. 选择其中一类交易进行验证
//		const targetClusterID = 1 // 我们选择验证第 0 类
//		txsToVerify := clusters[targetClusterID]
//		txCountInCluster := len(txsToVerify)
//
//		t.Logf("准备验证第 %d 类的 %d 个交易...", targetClusterID, txCountInCluster)
//
//		// 5. 调用 CalculateRequiredHashes2 函数计算所需哈希数量
//		startTime = time.Now()
//		requiredHashesCount := trie.CalculateRequiredHashes2(txsToVerify)
//		calcDuration := time.Since(startTime)
//
//		t.Logf(">>> 结果: 验证第 %d 类的 %d 个交易，需要 %d 个额外哈希，计算耗时: %v",
//			targetClusterID, txCountInCluster, requiredHashesCount, calcDuration)
//
//		// 6. 断言与逻辑验证
//		if requiredHashesCount <= 0 {
//			t.Errorf("错误: 当只验证部分交易时，所需哈希数应该大于 0, 实际为 %d", requiredHashesCount)
//		}
//
//		// MPT 证明所需哈希数的理论上限大约是 N * log16(M)，其中 N 是目标交易数，M是总交易数。
//		// 一个更宽松但绝对正确的断言是，所需哈希数不会超过总交易数。
//		if requiredHashesCount >= totalTxCount {
//			t.Errorf("错误: 所需哈希数 (%d) 不应大于或等于总交易数 (%d)", requiredHashesCount, totalTxCount)
//		}
//
// }
package merkle

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"math"
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

// TestGetRequiredHashesForTxs_MT tests the scenario with multiple clusters for MT
func TestGetRequiredHashesForTxs_MT(t *testing.T) {
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

	// 3. Build MPT
	t.Log("Building MPT with all transactions...")
	startTime := time.Now()
	trie := NewMerkleTree(allTxs)
	duration := time.Since(startTime)
	t.Logf("Merkle tree built in %v with %d leaves.", duration, len(allTxs))
	t.Logf("Tree root hash: %s", trie.Root.Hash.Hex())

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

			// Select clusters in order
			for i := 0; i < tc.clustersToRequest; i++ {
				clusterID := i % clusterCount // Select clusters in order
				selectedClusters = append(selectedClusters, clusterID)
				txsToVerify = append(txsToVerify, clusters[clusterID]...)
			}

			txCountInRequest := len(txsToVerify)
			t.Logf("Preparing to verify %d transactions from %d clusters...", txCountInRequest, tc.clustersToRequest)

			// 6. Call GetRequiredHashesForTxs method to calculate required hashes
			startTime := time.Now()
			requiredHashes := trie.GetRequiredHashes(txsToVerify)
			calcDuration := time.Since(startTime)

			t.Logf(">>> Result: Verifying %d transactions from %d clusters requires %d additional hashes, calculation time: %v",
				txCountInRequest, tc.clustersToRequest, requiredHashes, calcDuration)

			// 7. Assertions and logical validation
			if txCountInRequest > 0 && requiredHashes <= 0 {
				t.Errorf("Error: When verifying partial transactions, required hashes should be greater than 0, got %d", requiredHashes)
			}

			// For MPT trees, the required hashes should be proportional to the number of transactions
			// and the depth of the tree. We expect it to be less than the total number of transactions.
			if requiredHashes >= totalTxCount {
				t.Errorf("Error: Required hashes (%d) should not be greater than or equal to total transactions (%d)", requiredHashes, totalTxCount)
			}

			// Verify the result is not negative
			if requiredHashes < 0 {
				t.Errorf("Expected non-negative required hashes, got %d", requiredHashes)
			}

			// Verify the result when requesting all tx
			if tc.clustersToRequest == clusterCount && requiredHashes != 0 {
				t.Errorf("Expected zeor required hashes, got %d", requiredHashes)

			}

			// Additional MPT-specific assertion: For MPT, the number of required hashes
			// should be roughly proportional to the number of transactions being verified
			// and the depth of the tree (log16(N) for hexary MPT)
			expectedUpperBound := txCountInRequest * int(math.Ceil(math.Log(float64(totalTxCount))/math.Log(16)))
			if requiredHashes > expectedUpperBound {
				t.Logf("Warning: Required hashes (%d) exceeds expected upper bound (%d) for MPT",
					requiredHashes, expectedUpperBound)
			}
		})
	}
}
