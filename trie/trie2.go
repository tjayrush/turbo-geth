// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty off
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package trie implements Merkle Patricia Tries.
package trie

import (
	"bytes"
	"context"
	"fmt"
	"math/bits"

	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/dbutils"
	"github.com/ledgerwatch/turbo-geth/ethdb"
)

type Trie2 struct {
	ethdb.Database
}

func NewTrie2() *Trie2 {
	return &Trie2{
		Database: ethdb.NewObjectDatabase(ethdb.NewBolt().InMem().MustOpen()),
	}
}

func (t *Trie2) KV() ethdb.KV {
	return t.Database.(ethdb.HasKV).KV()
}

func (t *Trie2) FindSubTriesToLoad(rl *RetainList) (prefixes [][]byte, fixedbits []int) {
	_ = t.KV().View(context.Background(), func(tx ethdb.Tx) error {
		ih := tx.Bucket(dbutils.IntermediateTrieHashBucket).Cursor()
		parent := make([]byte, 0, common.HashLength*4+common.IncarnationLength*2) // longest storage key as nibbles
		parentV := make([]byte, 0, common.HashLength)

		k, v, err := ih.First()
		//fmt.Printf("First()%x \n", k)
		for k != nil {
			if err != nil {
				return err
			}
			if !rl.Retain(k) {
				next, ok := dbutils.NextSubtreeHex(k)
				if !ok {
					break
				}
				if !bytes.HasPrefix(next, parent) {
					next, ok = dbutils.NextSubtreeHex(parent)
					if !ok {
						break
					}
				}
				k, v, err = ih.Seek(next)
				//fmt.Printf("Seek(%x)%x \n", next, k)
				if err != nil {
					return err
				}
				if bytes.HasPrefix(k, parent) { // handle child
					continue
				}
				//fmt.Printf("Sibling: %x, not under %x\n", k, parent)
				parent = append(parent[:0], k...) // go to next trie
				parentV = append(parentV[:0], v...)
				continue
			}
			parent = append(parent[:0], k...)
			parentV = append(parentV[:0], v...)
			k, v, err = ih.Next()
			//fmt.Printf("Next()%x \n", k)
			if err != nil {
				return err
			}
			if bytes.HasPrefix(k, parent) { // handle child
				continue
			}

			//fmt.Printf("Child: %x , not under %x\n", k, parent)
			if len(parentV) > 0 { // if not empty root
				v := common.CopyBytes(parent)
				dropEvenNibble := len(v) % 2
				CompressNibbles(v[:len(v)-dropEvenNibble], &v)
				//fmt.Printf("Found: %x\n", v)
				prefixes = append(prefixes, v) // handle leaf
			}
			parent = append(parent[:0], k...) // go to next trie
		}
		return nil
	})
	return prefixes, fixedbits
}

type Trie2HashBilder struct {
	*HashBuilder
	trie2 *Trie2
	hc    HashCollector
	batch ethdb.DbWithPendingMutations

	branchChildren map[uint][]byte
	accKey         []byte
}

func NewTrie2HashBuilder(hb *HashBuilder) *Trie2HashBilder {
	return &Trie2HashBilder{HashBuilder: hb, accKey: make([]byte, 32)}
}

func (hb *Trie2HashBilder) Reset() {
	if hb.batch == nil {
		hb.batch = hb.trie2.NewBatch()
	}
	hb.batch.Rollback()
	hb.accKey = hb.accKey[:0]
	hb.branchChildren = make(map[uint][]byte)
	hb.HashBuilder.Reset()
}

//func (hb *Trie2HashBilder) leaf(length int, keyHex []byte, val rlphacks.RlpSerializable) error {
//	k := make([]byte, 128)
//	copy(k, keyHex[:64])
//	copy(k, keyHex[80:144])
//	if err := hb.batch.Put(dbutils.IntermediateTrieHashBucket, k, common.CopyBytes(val.RawBytes())); err != nil {
//		return err
//	}
//	if err := hb.HashBuilder.leaf(length, keyHex, val); err != nil {
//		return err
//	}
//	return nil
//}

func (hb *Trie2HashBilder) branch(set uint16) error {
	if hb.branchChildren == nil {
		hb.branchChildren = make(map[uint][]byte)
	}

	digits := bits.OnesCount16(set)
	if len(hb.nodeStack) < digits {
		return fmt.Errorf("len(hb.nodeStask) %d < digits %d", len(hb.nodeStack), digits)
	}
	nodes := hb.nodeStack[len(hb.nodeStack)-digits:]
	hashes := hb.hashStack[len(hb.hashStack)-hashStackStride*digits:]
	var i int
	for digit := uint(0); digit < 16; digit++ {
		if ((uint16(1) << digit) & set) != 0 {
			if nodes[i] == nil {
				hb.branchChildren[digit] = common.CopyBytes(hashes[hashStackStride*i+1 : hashStackStride*(i+1)])
			}
			i++
		}
	}

	return hb.HashBuilder.branch(set)
}

//func (hb *Trie2HashBilder) accountLeaf(length int, keyHex []byte, balance *uint256.Int, nonce uint64, incarnation uint64, fieldSet uint32) error {
//	var accCopy accounts.Account
//	accCopy.Copy(&hb.acc)
//	CompressNibbles(keyHex[:64], &hb.accKey)
//	hb.trie2.accs[common.BytesToHash(hb.accKey)] = &accCopy
//
//	var val []byte
//	if fieldSet&uint32(4) != 0 {
//		copy(hb.accRoot[:], hb.hashStack[len(hb.hashStack)-common.HashLength:len(hb.hashStack)])
//		if hb.accRoot == EmptyRoot {
//			val = []byte{}
//		} else {
//			val = common.CopyBytes(hb.accRoot[:])
//		}
//	} else {
//		val = []byte{}
//	}
//
//	if err := hb.batch.Put(dbutils.IntermediateTrieHashBucket, common.CopyBytes(keyHex[:64]), val); err != nil {
//		return err
//	}
//
//	return hb.HashBuilder.accountLeaf(length, keyHex, balance, nonce, incarnation, fieldSet)
//}

func (hb *Trie2HashBilder) wrapHashCollector(hc HashCollector) HashCollector {
	hb.hc = hc
	return hb.hashCollector
}

func (hb *Trie2HashBilder) rootHash() common.Hash {
	if _, err := hb.batch.Commit(); err != nil {
		panic(err)
	}
	return hb.HashBuilder.rootHash()
}

func (hb *Trie2HashBilder) hashCollector(keyHex []byte, hash []byte) error {
	if hb.hc != nil {
		if err := hb.hc(keyHex, hash); err != nil {
			return err
		}
	}

	if len(keyHex) == 0 || hash == nil || len(keyHex) > common.HashLength*2 {
		return nil
	}

	k := common.CopyBytes(keyHex)
	if err := hb.batch.Put(dbutils.IntermediateTrieHashBucket, k, common.CopyBytes(hash)); err != nil {
		return err
	}
	for i, v := range hb.branchChildren {
		if err := hb.batch.Put(dbutils.IntermediateTrieHashBucket, append(k, byte(i)), v); err != nil {
			return err
		}
	}

	hb.branchChildren = make(map[uint][]byte)
	return nil
}

//type CursorWrapper struct {
//	trieRead ethdb.Cursor
//	dbRead   ethdb.Cursor
//	k        []byte // compressed
//	kHex     []byte // uncompressed
//}
//
//func WrapCursor(trieRead, dbRead ethdb.Cursor) *CursorWrapper {
//	return &CursorWrapper{
//		trieRead: trieRead,
//		dbRead:   dbRead,
//		k:        make([]byte, 0, common.HashLength*2+common.IncarnationLength),   // longest storage key
//		kHex:     make([]byte, 0, common.HashLength*4+common.IncarnationLength*2), // longest storage key as nibbles
//	}
//}
//
//func (c *CursorWrapper) SeekTo(seek []byte) ([]byte, []byte, error) {
//	k, v, err := c.trieRead.SeekTo(seek)
//	if err != nil {
//		return nil, nil, err
//	}
//	if bytes.Equal(k, seek) {
//		c.kHex = k
//		return c.kHex, v, nil
//	}
//	k, v, err = c.dbRead.SeekTo(seek)
//	if err != nil {
//		return nil, nil, err
//	}
//	DecompressNibbles(k, &c.kHex)
//	return c.kHex, v, nil
//}
//
//func (c *CursorWrapper) Next() ([]byte, []byte, error) {
//	k, v, err := c.trieRead.Next()
//	if err != nil {
//		return nil, nil, err
//	}
//	//c.kHex
//	k, v, err = c.dbRead.Next()
//	if err != nil {
//		return nil, nil, err
//	}
//	DecompressNibbles(k, &c.kHex)
//	return c.kHex, v, nil
//}
