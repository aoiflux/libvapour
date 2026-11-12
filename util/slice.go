package util

// offset+length can overflow int and pass a bounds test; len(buf)-offset
// cannot once offset is known to be in range.
func SafeSubslice(buf []byte, offset int, length int) ([]byte, bool) {
	if offset < 0 || length < 0 || offset > len(buf) || length > len(buf)-offset {
		return nil, false
	}
	return buf[offset : offset+length], true
}
