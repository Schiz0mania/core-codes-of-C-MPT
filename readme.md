# Core Simulation Code for Authenticated Data Structures in Blockchain Merkle Proofs

This repository provides the **core, runnable Go code and key configuration files** supporting the synthetic experiments described in our research article. The included materials are sufficient for readers to reproduce the synthetic experiments and inspect the evaluation pipeline. Due to confidentiality obligations, full proprietary testbed code and real-world datasets cannot be released; instead, we offer comprehensive implementations and synthetic samples for transparency and reproducibility.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Directory Structure](#directory-structure)
- [Installation & Deployment](#installation--deployment)
- [Usage](#usage)
- [Configuration](#configuration)
- [Data Information](#data-information)
- [Testing](#testing)
- [Citation & Contact](#citation--contact)

---

## Project Overview

This project is designed for simulating and evaluating multiple authenticated data structures in blockchain environments, focusing on Merkle Tree, k-Merkle Tree, Merkle Patricia Trie(MPT), Clustered-Merkle Patricia Trie(CMPT), and Verkle Tree. The code is directly runnable in a local Go environment, making it easy to reproduce synthetic experiments described in our manuscript.

---

## Features

- **Multiple Data Structure Implementations:**  
  Includes classic Merkle Tree, k-Merkle Tree, MPT, C-MPT, and Verkle Tree.

- **Core Experimental Logic:**  
  Supports tree construction, hash counting, and proof  evaluation.

- **Synthetic Data Generator:**  
  Provides signed transactions(ethereum standard) that mimic workload characteristics (no real EHRs or confidential info).

- **Test Harness:**  
  Each structure has an independent test file for direct evaluation.

---

## Directory Structure

```
mytrees/                
├── cmpt/
│   ├── ClusteredMerklePatriciaTrie.go
│   └── cmpt_test.go
├── kmerkle/
│   ├── K-MerkleTree.go
│   └── kmerkle_test.go
├── merkle/
│   ├── MerkleTree.go
│   └── merkle_test.go
├── mpt/
│   ├── MerklePatriciaTrie.go
│   └── mpt_test.go
└── verkle/
    ├── VerkleTree.go
    └── verkle_test.go
    ...

```


---

## Installation & Deployment

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Schiz0mania/core-codes-of-C-MPT.git
   ```

2. **Install Go Dependencies**
    - Requires Go 1.23 or later.
   ```bash
   go mod tidy
   ```

3. **Run Tests or Main Program**
    - Run all tests:
      ```bash
      go test ./...
      ```
    - Or run a specific test file:
      ```bash 
      go test -v cmpt/ClusteredMerklePatriciaTrie.go cmpt/cmpt_test.go
      ```
      ```bash
      go test -v kmerkle/K-MerkleTree.go kmerkle/kmerkle_test.go
      ```
      ```bash
      go test -v merkle/MerkleTree.go merkle/merkle_test.go
      ```
      ```bash
      go test -v mpt/MerklePatriciaTrie.go mpt/mpt_test.go
      ```
      ```bash
      go test -v verkle/VerkleTree.go verkle/verkle_test.go
      ```

---

## Usage

- Parameters (e.g., dataset size, required transaction types) can be adjusted at the top of implementation or test files.
- Running the test scripts outputs key experimental results such as construct time, branching stats, and hash requirements for proofs.
- The synthetic data generator quickly produces sample transaction datasets; no real assets or services required.

---

## Configuration

- Main parameters (tree type, branching factor, dataset scale) are set in each test file.
- You may adjust these according to the scenarios and comparisons described in the paper.

---

## Data Information

- All data provided is synthetically generated and contains **no real EHRs or sensitive information**.


---

## Testing

- Each data structure has a dedicated test file. Run tests to obtain experiment statistics and evaluate proof efficiency.
- Main outputs include tree depth, number of children, and hash counts for single/multi-transaction proofs.

---

## Citation & Contact

- If you use this code for research, please cite the corresponding article and this repository.
- For questions, requests, or suggestions, please open an issue or contact the author.

---

> This project adheres to the principles of reproducibility and transparency. All synthetic experiments and key implementations are directly runnable locally. For further extension or integration into Geth environments, refer to the article setup.
