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

	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/dbutils"
	"github.com/ledgerwatch/turbo-geth/ethdb"
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

func (t *Trie2) FindSubTriesToLoad(rl *RetainList) {
	kHex := make([]byte, 0, common.HashLength*4+common.IncarnationLength*2) // longest storage key as nibbles
	_ = t.KV().Update(context.Background(), func(tx ethdb.Tx) error {
		c := tx.Bucket(dbutils.CurrentStateBucket).Cursor()
		ih := tx.Bucket(dbutils.IntermediateTrieHashBucket).Cursor()
		for ihK, ihV, err := ih.First(); ihK != nil; ihK, ihV, err = ih.Next() {
			if err != nil {
				return err
			}

			if len(ihV) == 0 {
				continue
			}

			DecompressNibbles(ihK, &kHex)
			for k, _, err := c.SeekTo(kHex); k != nil; k, _, err = ih.Next() {
				if err != nil {
					return err
				}
				if !bytes.HasPrefix(k, kHex) {
					break
				}
				c.Delete(k)
			}
		}
		return nil
	})

	_ = t.KV().View(context.Background(), func(tx ethdb.Tx) error {
		ih := tx.Bucket(dbutils.IntermediateTrieHashBucket).Cursor()
		for k, _, err := ih.First(); k != nil; k, _, err = ih.Next() {
			if err != nil {
				return err
			}
			DecompressNibbles(k, &kHex)
			rl.AddHex(k)
		}
		return nil
	})

	_ = t.KV().View(context.Background(), func(tx ethdb.Tx) error {
		ih := tx.Bucket(dbutils.CurrentStateBucket).Cursor()
		for k, _, err := ih.First(); k != nil; k, _, err = ih.Next() {
			if err != nil {
				return err
			}
			if !rl.Retain(k) {
				// add to dbPrefixes?
			}
		}
		return nil
	})
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
