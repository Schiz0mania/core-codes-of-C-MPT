package cmpt

import (
	_ "bytes"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	_ "math/big"
	"math/rand"
	"testing"
	"time"
	_ "time"

	"github.com/ethereum/go-ethereum/common"
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

func TestCalculateRequiredHashes_Clustered(t *testing.T) {
	// 1. Setup simulation environment
	signer := types.LatestSigner(params.TestChainConfig)
	const totalTxCount = 5000
	const clusterCount = 256

	// 1.1 Generate 32 fixed, random prefixes as cluster keys
	prefixes := make([][]byte, clusterCount)
	for i := 0; i < clusterCount; i++ {
		prefix := make([]byte, 8) // Use 8-byte prefixes
		if _, err := rand.Read(prefix); err != nil {
			t.Fatalf("Failed to generate random prefix: %v", err)
		}
		prefixes[i] = prefix
	}

	// 1.2 Create 1000 transactions and group them into 32 clusters
	t.Logf("Generating %d transactions into %d clusters...", totalTxCount, clusterCount)
	// Use a map to store clusters: key is prefix, value is list of transactions under that prefix
	clusters := make(map[string][]*types.Transaction)
	// For quick lookup of which prefix a transaction belongs to
	txToPrefix := make(map[common.Hash][]byte)

	for i := 0; i < totalTxCount; i++ {
		tx := newTestTx(signer, uint64(i), 100)

		prefix := prefixes[rand.Intn(clusterCount)]

		prefixStr := string(prefix)
		clusters[prefixStr] = append(clusters[prefixStr], tx)
		txToPrefix[tx.Hash()] = prefix
	}

	// 2. Build the clustered MPT
	t.Log("Building clustered MPT using BuildCMPTTree...")
	trie := NewTrie()
	builtTrie, duration := BuildCMPTTree(trie, clusters)
	trie = builtTrie // Use the constructed Trie
	t.Logf("MPT built in %v with %d leaves (one for each cluster).", duration, len(clusters))
	t.Logf("Tree root hash: %s", trie.Root.GetHash().Hex())

	// 3. Define test cases (based on number of clusters requested)
	testCases := []struct {
		name              string
		clustersToRequest int // Number of clusters to request transactions from
	}{
		{"Requesting txs from 1 cluster", 0},
		{"Requesting txs from 1 cluster", 1},
		{"Requesting txs from 2 cluster", 2},
		{"Requesting txs from 4 cluster", 4},
		{"Requesting txs from 8 cluster", 8},
		{"Requesting txs from 16 cluster", 16},
		{"Requesting txs from 32 cluster", 32},
	}

	// 4. Execute and assert
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 4.1 Prepare input: take all transactions from each of the specified number of clusters
			var requestedTxs []*types.Transaction
			for i := 0; i < tc.clustersToRequest; i++ {
				prefixStr := string(prefixes[i])
				if clusterTxs, exists := clusters[prefixStr]; exists && len(clusterTxs) > 0 {
					// Append all transactions from this cluster to the requested list
					requestedTxs = append(requestedTxs, clusterTxs...)
				}
			}

			// 4.2 Core adaptation: Convert the list of requested transactions to their unique prefixes
			// Because CalculateRequiredHashes2 requires MPT keys
			uniquePrefixes := make(map[string]bool)
			for _, tx := range requestedTxs {
				prefix := txToPrefix[tx.Hash()]
				uniquePrefixes[string(prefix)] = true
			}

			var requestedKeys [][]byte
			for prefixStr := range uniquePrefixes {
				// Need to pass nibble-encoded keys
				requestedKeys = append(requestedKeys, keyToNibbles([]byte(prefixStr)))
			}

			// 4.3 Call the function and perform assertions
			// Note: The second parameter here is MPT keys (prefixes), not transaction hashes
			startTime := time.Now()
			requiredHashes := trie.CalculateRequiredHashes2(requestedKeys)
			calcDuration := time.Since(startTime)

			t.Logf("\n>>> Result: Verifying %d transactions from %d clusters requires %d additional hashes, calculation took: %v", len(requestedTxs), tc.clustersToRequest, requiredHashes, calcDuration)

			// Assertion: When all clusters are requested, required hashes should be 0
			if tc.clustersToRequest == clusterCount {
				if requiredHashes != 0 {
					t.Errorf("Expected 0 required hashes when all clusters are requested, but got %d", requiredHashes)
				}
			} else if requiredHashes == 0 && tc.clustersToRequest != 0 {
				t.Errorf("Expected non-zero required hashes when requesting from %d clusters, but got 0", tc.clustersToRequest)
			}
		})
	}
}
