package merkle

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

// TestGetRequiredHashesForTxs_MT tests the scenario with multiple clusters for MT
func TestGetRequiredHashesForTxs_MT(t *testing.T) {
	// Setup environment
	signer := types.LatestSigner(params.TestChainConfig)
	const totalTxCount = 5000
	const clusterCount = 256

	// Generate transactions and randomly distribute them into clusters
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

	// Build MPT
	t.Log("Building MPT with all transactions...")
	startTime := time.Now()
	trie := NewMerkleTree(allTxs)
	duration := time.Since(startTime)
	t.Logf("Merkle tree built in %v with %d leaves.", duration, len(allTxs))
	t.Logf("Tree root hash: %s", trie.Root.Hash.Hex())

	// Define test cases (based on requested number of clusters)
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

	// Run test cases
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

			// Call GetRequiredHashesForTxs method to calculate required hashes
			startTime := time.Now()
			requiredHashes := trie.GetRequiredHashes(txsToVerify)
			calcDuration := time.Since(startTime)

			t.Logf("\n>>> Result: Verifying %d transactions from %d clusters requires %d additional hashes, calculation time: %v",
				txCountInRequest, tc.clustersToRequest, requiredHashes, calcDuration)

			// Assertions and logical validation
			if txCountInRequest > 0 && requiredHashes <= 0 {
				t.Errorf("Error: When verifying partial transactions, required hashes should be greater than 0, got %d", requiredHashes)
			}

			// We expect it to be less than the total number of transactions.
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

		})
	}
}
