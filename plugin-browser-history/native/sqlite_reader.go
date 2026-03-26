package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

// sqliteReader is a minimal, read-only SQLite3 file parser.
// It supports only simple table B-trees (page types 0x05 and 0x0D).
// No WAL merging, no overflow page assembly for large payloads.
// Sufficient for reading URLs/titles from Chrome and Firefox history files.
type sqliteReader struct {
	data     []byte
	pageSize int
}

// sqlRow is a slice of column values: nil, int64, float64, string, or []byte.
type sqlRow []interface{}

func newSQLiteReader(path string) (*sqliteReader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 100 {
		return nil, fmt.Errorf("sqlite: file too small")
	}
	if string(data[:16]) != "SQLite format 3\x00" {
		return nil, fmt.Errorf("sqlite: not a SQLite3 file")
	}
	ps := int(binary.BigEndian.Uint16(data[16:18]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 {
		return nil, fmt.Errorf("sqlite: invalid page size %d", ps)
	}
	return &sqliteReader{data: data, pageSize: ps}, nil
}

func (r *sqliteReader) page(n int) ([]byte, error) {
	start := (n - 1) * r.pageSize
	end := start + r.pageSize
	if n < 1 || end > len(r.data) {
		return nil, fmt.Errorf("sqlite: page %d out of range", n)
	}
	return r.data[start:end], nil
}

// sqlVarint reads a SQLite variable-length integer from data[off:].
// Returns the value and the number of bytes consumed.
func sqlVarint(data []byte, off int) (int64, int) {
	var val int64
	for i := 0; i < 9; i++ {
		if off+i >= len(data) {
			return val, i
		}
		b := data[off+i]
		if i == 8 {
			val = (val << 8) | int64(b)
			return val, 9
		}
		val = (val << 7) | int64(b&0x7F)
		if b&0x80 == 0 {
			return val, i + 1
		}
	}
	return val, 9
}

// ReadTable returns all rows from the named table.
func (r *sqliteReader) ReadTable(name string) ([]sqlRow, error) {
	root, err := r.schemaRoot(name)
	if err != nil {
		return nil, err
	}
	var rows []sqlRow
	if err := r.walk(root, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// schemaRoot reads sqlite_master (page 1) to find the root page for a table.
func (r *sqliteReader) schemaRoot(name string) (int, error) {
	var rows []sqlRow
	if err := r.walk(1, &rows); err != nil {
		return 0, err
	}
	for _, row := range rows {
		// sqlite_master columns: type, name, tbl_name, rootpage, sql
		if len(row) < 5 {
			continue
		}
		typ, _ := row[0].(string)
		rname, _ := row[1].(string)
		root, _ := row[3].(int64)
		if typ == "table" && rname == name && root > 0 {
			return int(root), nil
		}
	}
	return 0, fmt.Errorf("sqlite: table %q not found", name)
}

// walk recursively collects rows from a B-tree rooted at pageNum.
func (r *sqliteReader) walk(pageNum int, rows *[]sqlRow) error {
	pg, err := r.page(pageNum)
	if err != nil {
		return err
	}

	hdrOff := 0
	if pageNum == 1 {
		hdrOff = 100 // skip 100-byte DB header on page 1
	}
	if hdrOff >= len(pg) {
		return nil
	}

	switch pg[hdrOff] {
	case 0x0D: // leaf table B-tree page
		return r.walkLeaf(pg, hdrOff, rows)
	case 0x05: // interior table B-tree page
		return r.walkInterior(pg, hdrOff, rows)
	default:
		// index pages or unknown — skip
		return nil
	}
}

func (r *sqliteReader) walkLeaf(pg []byte, hdrOff int, rows *[]sqlRow) error {
	if hdrOff+8 > len(pg) {
		return nil
	}
	numCells := int(binary.BigEndian.Uint16(pg[hdrOff+3 : hdrOff+5]))
	ptrBase := hdrOff + 8

	for i := 0; i < numCells; i++ {
		pOff := ptrBase + i*2
		if pOff+2 > len(pg) {
			break
		}
		cellOff := int(binary.BigEndian.Uint16(pg[pOff : pOff+2]))
		if cellOff == 0 || cellOff >= len(pg) {
			continue
		}

		// leaf cell: varint(payloadSize) varint(rowid) payload [overflow-page-ptr]
		payloadSize, n1 := sqlVarint(pg, cellOff)
		if n1 == 0 {
			continue
		}
		_, n2 := sqlVarint(pg, cellOff+n1)
		if n2 == 0 {
			continue
		}
		payStart := cellOff + n1 + n2
		payEnd := payStart + int(payloadSize)
		if payEnd > len(pg) {
			payEnd = len(pg) // truncate — overflow not supported
		}
		if payStart >= payEnd {
			continue
		}
		row, err := parseRecord(pg[payStart:payEnd])
		if err != nil {
			continue
		}
		*rows = append(*rows, row)
	}
	return nil
}

func (r *sqliteReader) walkInterior(pg []byte, hdrOff int, rows *[]sqlRow) error {
	if hdrOff+12 > len(pg) {
		return nil
	}
	numCells := int(binary.BigEndian.Uint16(pg[hdrOff+3 : hdrOff+5]))
	rightmost := int(binary.BigEndian.Uint32(pg[hdrOff+8 : hdrOff+12]))
	ptrBase := hdrOff + 12

	for i := 0; i < numCells; i++ {
		pOff := ptrBase + i*2
		if pOff+2 > len(pg) {
			break
		}
		cellOff := int(binary.BigEndian.Uint16(pg[pOff : pOff+2]))
		if cellOff+4 > len(pg) {
			continue
		}
		left := int(binary.BigEndian.Uint32(pg[cellOff : cellOff+4]))
		if left > 0 {
			if err := r.walk(left, rows); err != nil {
				return err
			}
		}
	}
	if rightmost > 0 {
		return r.walk(rightmost, rows)
	}
	return nil
}

// parseRecord decodes a SQLite record payload into a slice of column values.
func parseRecord(data []byte) (sqlRow, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty record")
	}
	hdrSize, n := sqlVarint(data, 0)
	if n == 0 || int(hdrSize) > len(data) {
		return nil, fmt.Errorf("bad header size")
	}

	var types []int64
	off := n
	for off < int(hdrSize) {
		st, sn := sqlVarint(data, off)
		if sn == 0 {
			break
		}
		types = append(types, st)
		off += sn
	}

	var row sqlRow
	bodyOff := int(hdrSize)
	for _, st := range types {
		val, sz := decodeValue(data, bodyOff, st)
		row = append(row, val)
		bodyOff += sz
	}
	return row, nil
}

func decodeValue(data []byte, off int, serialType int64) (interface{}, int) {
	avail := len(data) - off
	if avail < 0 {
		avail = 0
	}
	switch serialType {
	case 0:
		return nil, 0
	case 1:
		if avail < 1 {
			return nil, 1
		}
		return int64(int8(data[off])), 1
	case 2:
		if avail < 2 {
			return nil, 2
		}
		return int64(int16(binary.BigEndian.Uint16(data[off:]))), 2
	case 3:
		if avail < 3 {
			return nil, 3
		}
		v := int64(data[off])<<16 | int64(data[off+1])<<8 | int64(data[off+2])
		if v&0x800000 != 0 {
			v |= ^int64(0xFFFFFF)
		}
		return v, 3
	case 4:
		if avail < 4 {
			return nil, 4
		}
		return int64(int32(binary.BigEndian.Uint32(data[off:]))), 4
	case 5:
		if avail < 6 {
			return nil, 6
		}
		v := int64(binary.BigEndian.Uint32(data[off:]))<<16 | int64(binary.BigEndian.Uint16(data[off+4:]))
		return v, 6
	case 6:
		if avail < 8 {
			return nil, 8
		}
		return int64(binary.BigEndian.Uint64(data[off:])), 8
	case 7:
		if avail < 8 {
			return nil, 8
		}
		// Float64 — return as int64 bits (not needed for URLs)
		return int64(binary.BigEndian.Uint64(data[off:])), 8
	case 8:
		return int64(0), 0
	case 9:
		return int64(1), 0
	}

	if serialType >= 12 {
		even := serialType%2 == 0
		var sz int
		if even {
			sz = int((serialType - 12) / 2) // BLOB
		} else {
			sz = int((serialType - 13) / 2) // TEXT
		}
		if sz < 0 {
			sz = 0
		}
		if sz > avail {
			sz = avail
		}
		if even {
			b := make([]byte, sz)
			copy(b, data[off:off+sz])
			return b, sz
		}
		return string(data[off : off+sz]), sz
	}
	return nil, 0
}
