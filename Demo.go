package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"time"
	"github.com/boltdb/bolt"
)

type Block struct {
	Timestamp     int64
	Data          []byte
	PrevBlockHash []byte
	Hash          []byte
	Nonce         int
}

// set Hash for a Block
func (b *Block) setHash() {
	timestamp := []byte(strconv.FormatInt(b.Timestamp, 10))
	headers := bytes.Join([][]byte{b.PrevBlockHash, b.Data, timestamp}, []byte{})
	hash := sha256.Sum256(headers)
	b.Hash = hash[:]
}

// create a Block
func newBlock(data string, prevBlockHash []byte) *Block {
	block := &Block{time.Now().Unix(), []byte(data), prevBlockHash, []byte{}, 0}

	// block.setHash()

	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()
	block.Hash = hash[:]
	block.Nonce = nonce
	return block
}

type Blockchain struct {
	blocks []*Block
}

func (bc *Blockchain) addBlock(data string) {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	prevHash := prevBlock.Hash
	bc.blocks = append(bc.blocks, newBlock(data, prevHash))
}

func newGenesisBlock() *Block {
	return newBlock("Genesis Block", []byte{})
}

func newBlockchain() *Blockchain {
	return &Blockchain{[]*Block{newGenesisBlock()}}
	db, err := bolt.Open(dbFile.db, 0600, nil)
	
}

const targetBits = 4

type ProofOfWork struct {
	block  *Block
	target *big.Int
}

func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))
	return &ProofOfWork{b, target}
}

func (pow *ProofOfWork) prepareData(nonce int) []byte {
	Timestamp_hex := []byte(strconv.FormatInt(pow.block.Timestamp, 16))
	TargetBits_hex := []byte(strconv.FormatInt(targetBits, 16))
	Nonce_hex := []byte(strconv.FormatInt(int64(nonce), 16))

	data := bytes.Join([][]byte{
		pow.block.PrevBlockHash,
		pow.block.Data,
		Timestamp_hex,
		TargetBits_hex,
		Nonce_hex,
	},
		[]byte{},
	)
	return data
}

/*
1. Chuẩn bị data
2. Hash data với thuật toán SHA-256
3. Chuyển hash sang big.Int
4. So sánh con số nhận được với targe
*/
func (pow *ProofOfWork) Run() (int, []byte) {
	var hashInt big.Int
	var hash [32]byte
	var nonce int
	maxNonce := math.MaxInt64

	fmt.Printf("Mining the block containing \"%s\"...", pow.block.Data)

	for nonce = 0; nonce < maxNonce; nonce++ {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)
		// fmt.Printf("\n%x", hash)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			break
		}
	}

	fmt.Printf("\n\n")
	return nonce, hash[:]
}

// verify result pow
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int
	data := pow.prepareData(pow.block.Nonce)
	data_hash := sha256.Sum256(data)
	hashInt.SetBytes(data_hash[:])
	isValid := hashInt.Cmp(pow.target) == -1
	return isValid
}

//Serialize
func (b *Block) Serialize() []byte{
	var result bytes.Buffer
	enconder := gob.NewEncoder(&result)
	enconder.Encode(b)
	return result.Bytes()
}

//Deserialize
func DeserializeBlock(d []byte) *Block{
	var b Block
	decoder := gob.NewDecoder(bytes.NewReader(d))
	decoder.Decode(&b)
	return &b
}

func main() {
	bc := newBlockchain()
	bc.addBlock("Send 1 to Nga")
	bc.addBlock("Send 2 to Khanh")

	for _, block := range bc.blocks {
		fmt.Printf("Prev.Hash: %x\n", block.PrevBlockHash)
		fmt.Printf("Data: %s\n", block.Data)
		fmt.Printf("Hash: %x\n", block.Hash)
		// fmt.Printf("hi")
		fmt.Println()
		pow := NewProofOfWork(block)
		fmt.Printf("Pow: %s\n", strconv.FormatBool(pow.Validate()))
		fmt.Printf("-------------------------------------\n")
	}
}
