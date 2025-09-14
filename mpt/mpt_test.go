package mpt

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

// TestGetRequiredHashesForTxs_MPT tests the scenario with multiple clusters for MPT
func TestCalculateRequiredHashes_MPT(t *testing.T) {
	// Setup simulation environment
	signer := types.LatestSigner(params.TestChainConfig)
	const totalTxCount = 5000
	const clusterCount = 256

	// random prefixes as cluster keys
	prefixes := make([][]byte, clusterCount)
	for i := 0; i < clusterCount; i++ {
		prefix := make([]byte, 8) // Use 8-byte prefix
		if _, err := rand.Read(prefix); err != nil {
			t.Fatalf("Failed to generate random prefix: %v", err)
		}
		prefixes[i] = prefix
	}

	// Create transactions and group them into clusters
	t.Logf("Generating %d transactions into %d clusters...", totalTxCount, clusterCount)
	// Use map to store clusters: key is prefix, value is list of transactions under that prefix
	clusters := make(map[string][]*types.Transaction)
	// Slice of all transactions
	allTxs := make([]*types.Transaction, totalTxCount)

	for i := 0; i < totalTxCount; i++ {
		tx := newTestTx(signer, uint64(i), 100)
		// Random assignment
		prefix := prefixes[rand.Intn(clusterCount)]
		allTxs[i] = tx
		prefixStr := string(prefix)
		clusters[prefixStr] = append(clusters[prefixStr], tx)
	}

	// 2. Build MPT
	t.Log("Building MPT with all transactions...")
	trie := NewTrie()
	_, duration := BuildMPTTree(trie, allTxs)
	t.Logf("MPT build time: %v", duration)
	t.Logf("Tree root hash: %s", trie.Root.GetHash().Hex())

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

	// Execute and assert
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Collect all transactions from requested clusters
			var requestedTxs []*types.Transaction

			if tc.clustersToRequest > 0 {
				// Select specified number of clusters sequentially
				selectedClusters := make(map[int]bool)
				for i := 0; i < tc.clustersToRequest; i++ {
					selectedClusters[i] = true
				}

				// Collect transactions from selected clusters
				for clusterIdx := range selectedClusters {
					prefixStr := string(prefixes[clusterIdx])
					requestedTxs = append(requestedTxs, clusters[prefixStr]...)
				}
			}

			// Call CalculateRequiredHashes2
			startTime := time.Now()
			needs := trie.CalculateRequiredHashes2(requestedTxs)
			calcDuration := time.Since(startTime)

			t.Logf("\n>>> Result: Verifying %d transactions from %d clusters requires %d additional hashes, calculation took: %v", len(requestedTxs), tc.clustersToRequest, needs, calcDuration)

			// Assertion logic
			if tc.clustersToRequest == 0 {
				if needs != 0 {
					t.Errorf("Expected 0 required hashes when 0 clusters are requested, but got %d", needs)
				}
			}

			// Boundary assertion: when requesting all clusters, required hashes must be 0
			if tc.clustersToRequest == clusterCount {
				if needs != 0 {
					t.Errorf("Expected 0 required hashes when all clusters are requested, but got %d", needs)
				}
			}
		})
	}
}
