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
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/dbutils"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/trie/rlphacks"
)

type Trie2 struct {
	ethdb.Database
}

func NewTrie2() *Trie2 {
	return &Trie2{
		ethdb.NewObjectDatabase(ethdb.NewBolt().InMem().MustOpen()),
	}
}

func (t *Trie2) KV() ethdb.KV {
	return t.Database.(ethdb.HasKV).KV()
}

func (t *Trie2) FindSubTriesToLoad(rl *RetainList) (prefixes [][]byte, fixedbits []int) {
	//kHex := make([]byte, 0, common.HashLength*4+common.IncarnationLength*2) // longest storage key as nibbles
	//_ = t.KV().Update(context.Background(), func(tx ethdb.Tx) error {
	//	c := tx.Bucket(dbutils.CurrentStateBucket).Cursor()
	//	ih := tx.Bucket(dbutils.IntermediateTrieHashBucket).Cursor()
	//	for ihK, ihV, err := ih.First(); ihK != nil; ihK, ihV, err = ih.Next() {
	//		if err != nil {
	//			return err
	//		}
	//
	//		if len(ihV) == 0 {
	//			continue
	//		}
	//
	//		DecompressNibbles(ihK, &kHex)
	//		for k, _, err := c.SeekTo(kHex); k != nil; k, _, err = ih.Next() {
	//			if err != nil {
	//				return err
	//			}
	//			if !bytes.HasPrefix(k, kHex) {
	//				break
	//			}
	//			c.Delete(k)
	//		}
	//	}
	//	return nil
	//})

	//_ = t.KV().View(context.Background(), func(tx ethdb.Tx) error {
	//	ih := tx.Bucket(dbutils.IntermediateTrieHashBucket).Cursor()
	//	for k, _, err := ih.First(); k != nil; k, _, err = ih.Next() {
	//		if err != nil {
	//			return err
	//		}
	//		DecompressNibbles(k, &kHex)
	//		rl.AddHex(k)
	//	}
	//	return nil
	//})

	var ok bool
	var buf []byte
	inc := make([]byte, 8)
	_ = t.KV().View(context.Background(), func(tx ethdb.Tx) error {
		ih := tx.Bucket(dbutils.IntermediateTrieHashBucket).Cursor()
		c := tx.Bucket(dbutils.CurrentStateBucket).Cursor()
		next := []byte{}
		parent := make([]byte, 0, common.HashLength*4+common.IncarnationLength*2) // longest storage key as nibbles
		parentV := make([]byte, 0, common.HashLength)

		k, v, err := ih.First()
		fmt.Printf("First()%x \n", k)
		for k != nil {
			if err != nil {
				return err
			}
			//fmt.Printf("Retain: %t, %x \n", rl.Retain(k), k)
			if !rl.Retain(k) {
				next, ok = dbutils.NextSubtreeHex(k)
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
				fmt.Printf("Seek(%x)%x \n", next, k)
				if err != nil {
					return err
				}
				if bytes.HasPrefix(k, parent) { // handle child
					continue
				}
				fmt.Printf("Sibling: %x, not under %x\n", k, parent)
				//prefixes = append(prefixes, k)    // handle leaf
				parent = append(parent[:0], k...) // go to next trie
				parentV = append(parentV[:0], v...)
				continue
			}
			parent = append(parent[:0], k...)
			parentV = append(parentV[:0], v...)
			k, v, err = ih.Next()
			fmt.Printf("Next()%x \n", k)
			if err != nil {
				return err
			}
			if bytes.HasPrefix(k, parent) { // handle child
				if len(k) == common.HashLength*2 {
					CompressNibbles(k, &buf)
					cK, cV, err := c.Seek(buf)
					if err != nil {
						return err
					}
					if !bytes.Equal(cK, buf) {
						panic(fmt.Sprintf("%x!=%x\n", buf, cK))
					}

					copy(inc, cV)
				}
				continue
			}

			fmt.Printf("Child: %x , not under %x\n", k, parent)
			if len(parentV) > 0 { // if not empty root
				CompressNibbles(parent, &parent)
				var v []byte
				if len(parent) >= common.HashLength {
					v = make([]byte, len(parent)+common.IncarnationLength)
					copy(v[:32], parent[:32])
					copy(v[32:40], inc)
					copy(v[40:], parent[32:])
				} else {
					v = common.CopyBytes(parent)
				}
				fmt.Printf("Found: %x\n", v)
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
	trie2        *Trie2
	hc           HashCollector
	batch        ethdb.DbWithPendingMutations
	accountKey   []byte
	inc          uint64
	storageKey   []byte
	storageValue []byte

	accRoot        common.Hash
	branchChildren map[uint][]byte
}

func (hb *Trie2HashBilder) Reset() {
	if hb.batch == nil {
		hb.batch = hb.trie2.NewBatch()
	}
	hb.batch.Rollback()
}

func (hb *Trie2HashBilder) leaf(length int, keyHex []byte, val rlphacks.RlpSerializable) error {
	hb.storageKey = append(append(hb.storageKey[:0], hb.storageKey[:64]...), hb.storageKey[:64]...)
	if err := hb.batch.Put(dbutils.IntermediateTrieHashBucket, common.CopyBytes(hb.storageKey), common.CopyBytes(hb.storageValue)); err != nil {
		return err
	}
	if err := hb.HashBuilder.leaf(length, keyHex, val); err != nil {
		return err
	}
	return nil
}

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

func (hb *Trie2HashBilder) accountLeaf(length int, keyHex []byte, balance *uint256.Int, nonce uint64, incarnation uint64, fieldSet uint32) error {
	inc := make([]byte, 8)
	binary.BigEndian.PutUint64(inc, ^hb.inc)
	k := make([]byte, len(hb.accountKey)/2)
	CompressNibbles(hb.accountKey, &k)
	if err := hb.batch.Put(dbutils.CurrentStateBucket, k, inc); err != nil {
		return err
	}
	var val []byte
	copy(hb.accRoot[:], EmptyRoot[:])
	if fieldSet&uint32(4) != 0 {
		copy(hb.accRoot[:], hb.hashStack[len(hb.hashStack)-common.HashLength:len(hb.hashStack)])
		if hb.accRoot == EmptyRoot {
			val = []byte{}
		} else {
			val = common.CopyBytes(hb.accRoot[:])
		}
	} else {
		val = []byte{}
	}

	if err := hb.batch.Put(dbutils.IntermediateTrieHashBucket, common.CopyBytes(hb.accountKey), val); err != nil {
		return err
	}

	return hb.HashBuilder.accountLeaf(length, keyHex, balance, nonce, incarnation, fieldSet)
}

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

	if len(keyHex) == 0 || hash == nil {
		fmt.Printf("Skip???: %x\n", keyHex)
		return nil
	}

	dbutils.RemoveIncarnationFromKey(keyHex, &keyHex)
	fmt.Printf("Put parent: %x\n", keyHex)
	if err := hb.batch.Put(dbutils.IntermediateTrieHashBucket, common.CopyBytes(keyHex), common.CopyBytes(hash)); err != nil {
		return err
	}
	for k, v := range hb.branchChildren {
		fmt.Printf("Put child: %x\n", append(keyHex, byte(k)))
		if err := hb.batch.Put(dbutils.IntermediateTrieHashBucket, append(keyHex, byte(k)), v); err != nil {
			return err
		}
	}

	hb.branchChildren = make(map[uint][]byte)
	return nil
}

type CursorWrapper struct {
	trieRead ethdb.Cursor
	dbRead   ethdb.Cursor
	k        []byte // compressed
	kHex     []byte // uncompressed
}

func WrapCursor(trieRead, dbRead ethdb.Cursor) *CursorWrapper {
	return &CursorWrapper{
		trieRead: trieRead,
		dbRead:   dbRead,
		k:        make([]byte, 0, common.HashLength*2+common.IncarnationLength),   // longest storage key
		kHex:     make([]byte, 0, common.HashLength*4+common.IncarnationLength*2), // longest storage key as nibbles
	}
}

func (c *CursorWrapper) SeekTo(seek []byte) ([]byte, []byte, error) {
	k, v, err := c.trieRead.SeekTo(seek)
	if err != nil {
		return nil, nil, err
	}
	if bytes.Equal(k, seek) {
		c.kHex = k
		return c.kHex, v, nil
	}
	k, v, err = c.dbRead.SeekTo(seek)
	if err != nil {
		return nil, nil, err
	}
	DecompressNibbles(k, &c.kHex)
	return c.kHex, v, nil
}

func (c *CursorWrapper) Next() ([]byte, []byte, error) {
	k, v, err := c.trieRead.Next()
	if err != nil {
		return nil, nil, err
	}
	//c.kHex
	k, v, err = c.dbRead.Next()
	if err != nil {
		return nil, nil, err
	}
	DecompressNibbles(k, &c.kHex)
	return c.kHex, v, nil
}
