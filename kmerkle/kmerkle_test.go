package kmerkle

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	_ "math/big"
	"math/rand"
	"testing"
	"time"

	_ "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	_ "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
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

// TestKmerkleTree_MultipleClusters tests multiple cluster scenarios
func TestKmerkleTree_MultipleClusters(t *testing.T) {
	// Setup environment
	signer := types.LatestSigner(params.TestChainConfig)
	const totalTxCount = 5000
	const clusterCount = 256

	// Generate transactions and randomly distribute them into clusterCount clusters
	t.Logf("Generating %d transactions and randomly distributing them into %d clusters...", totalTxCount, clusterCount)
	allTxs := make([]*types.Transaction, totalTxCount)
	clusters := make(map[int][]*types.Transaction)

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

	// Build K-merkle tree with all transactions
	t.Log("Building K-merkle tree with all transactions...")
	startTime := time.Now()
	tree := NewFromTransactions(allTxs)
	buildDuration := time.Since(startTime)
	t.Logf("K-merkle tree built, time taken: %v", buildDuration)
	t.Logf("Tree root hash: %s", tree.Root.Hash.Hex())

	// Define test cases (based on number of requested clusters)
	testCases := []struct {
		name              string
		clustersToRequest int // Number of clusters to request transactions from
	}{
		{"Requesting txs from 0 clusters", 0},
		{"Requesting txs from 1 cluster", 1},
		{"Requesting txs from 2 clusters", 2},
		{"Requesting txs from 4 clusters", 4},
		{"Requesting txs from 8 clusters", 8},
		{"Requesting txs from 16 clusters", 16},
		{"Requesting txs from 32 clusters", 32},
	}

	// Execute and assert for each test case
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Collect transactions from requested clusters
			var txsToVerify []*types.Transaction

			if tc.clustersToRequest > 0 {
				// Select specified number of clusters sequentially
				for i := 0; i < tc.clustersToRequest; i++ {
					txsToVerify = append(txsToVerify, clusters[i]...)
				}
			}

			txCountInCluster := len(txsToVerify)

			// Call RequiredHashCountForTxs function to calculate required hash count
			startTime = time.Now()
			requiredHashesCount := tree.RequiredHashCountForTxs(txsToVerify)
			calcDuration := time.Since(startTime)

			t.Logf("\n>>> Result: Verifying %d transactions from %d clusters requires %d additional hashes, calculation took: %v",
				txCountInCluster, tc.clustersToRequest, requiredHashesCount, calcDuration)

			// Assertion and logic verification
			if tc.clustersToRequest == 0 {
				if requiredHashesCount != 0 {
					t.Errorf("Error: When verifying 0 clusters, required hash count should be 0, but got %d", requiredHashesCount)
				}
			} else if tc.clustersToRequest < clusterCount {
				if txCountInCluster > 0 && requiredHashesCount <= 0 {
					t.Errorf("Error: When verifying partial transactions, required hash count should be greater than 0, but got %d", requiredHashesCount)
				}
			}

			// when requesting all clusters, required hashes must be 0
			if tc.clustersToRequest == clusterCount {
				if requiredHashesCount != 0 {
					t.Errorf("Error: Expected 0 required hashes when all clusters are requested, but got %d", requiredHashesCount)
				}
			}

			// A more relaxed but absolutely correct assertion is that the required hash count should not exceed the total transaction count.
			if requiredHashesCount >= totalTxCount {
				t.Errorf("Error: Required hash count (%d) should not be greater than or equal to total transaction count (%d)", requiredHashesCount, totalTxCount)
			}
		})
	}
}
