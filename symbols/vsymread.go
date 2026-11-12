package symbols

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/aoiflux/libvapour/limits"
)

func ReadFile(path string) (*Table, error) {
	return ReadFileWith(path, ReadOptions{})
}

func ReadFileWith(path string, opts ReadOptions) (*Table, error) {
	opts, err := opts.Resolved()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("symbols: read table: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, opts.MaxTableFile+1))
	if err != nil {
		return nil, fmt.Errorf("symbols: read table %s: %w", path, err)
	}
	if int64(len(data)) > opts.MaxTableFile {
		return nil, fmt.Errorf("%w: %s is more than %d bytes", ErrTableTooLarge, path, opts.MaxTableFile)
	}
	return decodeTable(path, data, opts.MaxTableEntries)
}

func Read(name string, data []byte) (*Table, error) {
	return decodeTable(name, data, limits.DefaultMaxTableEntries)
}

func Decode(name string, data []byte) (*Table, error) {
	return decodeTable(name, data, limits.DefaultMaxTableEntries)
}

func decodeTable(name string, data []byte, margin int) (*Table, error) {
	d, err := DecodeDeclaration(data)
	if err != nil {
		return nil, fmt.Errorf("symbols: table %s: %w", name, err)
	}
	return assemble(name, d, margin)
}

// Anything that is not a JSON object with a "vsym" key is ErrNotVsym, so a
// file in another layout is told apart from a broken table.
func DecodeDeclaration(data []byte) (Declaration, error) {
	s := &scanner{data: data}
	var d Declaration
	var version, pointer *uint64
	var other error
	err := s.object(func(key string) error {
		var err error
		switch key {
		case "vsym":
			var v uint64
			if v, err = s.unsigned(); err == nil {
				if v != FormatVersion {
					return fmt.Errorf("symbols: format %d is not supported, only format %d", v, FormatVersion)
				}
				version = &v
			}
		case "pointer_width":
			var v uint64
			if v, err = s.unsigned(); err == nil {
				pointer = &v
			}
		case "windows_pdb":
			d.WindowsPDB, err = readPDB(s)
		case "linux_banner":
			var b string
			if b, err = s.str(); err == nil {
				d.LinuxBanner = []byte(b)
			}
		case "scalars":
			d.Scalars = []Scalar{}
			err = s.array(func() error {
				sc, err := readScalar(s)
				d.Scalars = append(d.Scalars, sc)
				return err
			})
		case "records":
			err = s.array(func() error {
				r, err := readRecord(s)
				d.Records = append(d.Records, r)
				return err
			})
		case "enumerations":
			err = s.array(func() error {
				e, err := readEnumeration(s)
				d.Enumerations = append(d.Enumerations, e)
				return err
			})
		case "addresses":
			err = s.array(func() error {
				a, err := readAddress(s)
				d.Addresses = append(d.Addresses, a)
				return err
			})
		default:
			if other == nil {
				other = fmt.Errorf("symbols: unknown key %q", key)
			}
			return s.skip(0)
		}
		return err
	})
	switch {
	case err != nil && version == nil && isScanError(err):
		return Declaration{}, fmt.Errorf("%w: %w", ErrNotVsym, err)
	case err != nil:
		return Declaration{}, wrapScan(err)
	case version == nil:
		return Declaration{}, fmt.Errorf(`%w: no "vsym" key`, ErrNotVsym)
	case other != nil:
		return Declaration{}, other
	case s.peek() != 0:
		return Declaration{}, fmt.Errorf("symbols: %w", s.fail("%v", errTrailing))
	case pointer == nil:
		return Declaration{}, errors.New(`symbols: no "pointer_width" key`)
	case *pointer != 4 && *pointer != 8:
		return Declaration{}, fmt.Errorf("symbols: pointer width %d is not 4 or 8", *pointer)
	}
	d.PointerWidth = uint8(*pointer)
	if err := d.check(); err != nil {
		return Declaration{}, err
	}
	return d, nil
}

func isScanError(err error) bool {
	var se *scanError
	return errors.As(err, &se)
}

func wrapScan(err error) error {
	if isScanError(err) && !strings.HasPrefix(err.Error(), "symbols: ") {
		return fmt.Errorf("symbols: %w", err)
	}
	return err
}

func unknownKey(s *scanner, what, key string) error {
	return s.fail("unknown key %q in %s", key, what)
}

func readPDB(s *scanner) (*PDBBuild, error) {
	var b PDBBuild
	var guid, age bool
	err := s.object(func(key string) error {
		var err error
		switch key {
		case "guid":
			guid = true
			if b.GUID, err = s.str(); err == nil && (len(b.GUID) != 32 || strings.ContainsFunc(b.GUID, notUpperHex)) {
				return s.fail("PDB GUID %q is not 32 upper-case hex digits", b.GUID)
			}
		case "age":
			age = true
			var v uint64
			if v, err = s.unsigned(); err == nil && v > math.MaxUint32 {
				return s.fail("PDB age %d is past 32 bits", v)
			}
			b.Age = uint32(v)
		case "file":
			if b.Database, err = s.str(); err == nil && b.Database == "" {
				return s.fail(`empty PDB "file"`)
			}
		default:
			return unknownKey(s, "windows_pdb", key)
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case !guid:
		return nil, s.fail(`windows_pdb has no "guid" key`)
	case !age:
		return nil, s.fail(`windows_pdb has no "age" key`)
	}
	return &b, nil
}

func notUpperHex(r rune) bool { return !('0' <= r && r <= '9' || 'A' <= r && r <= 'F') }

func readScalar(s *scanner) (Scalar, error) {
	var out Scalar
	var name, width, kind bool
	err := s.object(func(key string) error {
		var err error
		switch key {
		case "name":
			name = true
			out.Name, err = s.str()
		case "width":
			width = true
			out.Width, err = s.unsigned()
		case "kind":
			kind = true
			var k string
			k, err = s.str()
			out.Kind = ScalarKind(k)
		case "signed":
			out.Signed, err = s.boolean()
		case "big_endian":
			out.BigEndian, err = s.boolean()
		default:
			return unknownKey(s, "a scalar", key)
		}
		return err
	})
	switch {
	case err != nil:
		return out, err
	case !name, !width, !kind:
		return out, s.fail(`scalar %q needs "name", "width" and "kind"`, out.Name)
	}
	return out, nil
}

func readRecord(s *scanner) (Record, error) {
	var out Record
	var name bool
	err := s.object(func(key string) error {
		var err error
		switch key {
		case "name":
			name = true
			out.Name, err = s.str()
		case "width":
			out.Width, err = s.unsigned()
		case "members":
			err = s.array(func() error {
				m, err := readMember(s)
				out.Members = append(out.Members, m)
				return err
			})
		default:
			return unknownKey(s, "a record", key)
		}
		return err
	})
	if err == nil && !name {
		err = s.fail(`record has no "name" key`)
	}
	return out, err
}

func readMember(s *scanner) (Member, error) {
	var out Member
	var name, offset, typed, embeds bool
	err := s.object(func(key string) error {
		var err error
		switch key {
		case "name":
			name = true
			out.Name, err = s.str()
		case "offset":
			offset = true
			out.Offset, err = s.unsigned()
		case "type":
			typed = true
			var text string
			if text, err = s.str(); err == nil {
				if out.Type, err = parseTypeExpression(text); err != nil {
					return s.fail("%v", err)
				}
			}
		case "embeds":
			embeds = true
			if out.Embeds, err = s.str(); err == nil && out.Embeds == "" {
				return s.fail(`empty "embeds"`)
			}
		default:
			return unknownKey(s, "a member", key)
		}
		return err
	})
	switch {
	case err != nil:
		return out, err
	case !offset:
		return out, s.fail(`member %q has no "offset" key`, out.Name)
	case typed && embeds:
		return out, s.fail(`member %q has both "type" and "embeds"`, out.Name)
	case !typed && !embeds:
		return out, s.fail(`member %q has neither "type" nor "embeds"`, out.Name)
	case typed && !name:
		return out, s.fail(`a typed member has no "name" key`)
	}
	return out, nil
}

func readEnumeration(s *scanner) (EnumType, error) {
	var out EnumType
	var name bool
	err := s.object(func(key string) error {
		var err error
		switch key {
		case "name":
			name = true
			out.Name, err = s.str()
		case "width":
			out.Size, err = s.unsigned()
		case "constants":
			err = s.array(func() error {
				v, err := readConstant(s)
				out.Values = append(out.Values, v)
				return err
			})
		default:
			return unknownKey(s, "an enumeration", key)
		}
		return err
	})
	if err == nil && !name {
		err = s.fail(`enumeration has no "name" key`)
	}
	sortConstants(out.Values)
	return out, err
}

func readConstant(s *scanner) (EnumValue, error) {
	var out EnumValue
	var name, value bool
	err := s.object(func(key string) error {
		var err error
		switch key {
		case "name":
			name = true
			out.Name, err = s.str()
		case "value":
			value = true
			out.Value, err = s.signed()
		default:
			return unknownKey(s, "a constant", key)
		}
		return err
	})
	if err == nil && (!name || !value) {
		err = s.fail(`constant %q needs "name" and "value"`, out.Name)
	}
	return out, err
}

func readAddress(s *scanner) (Address, error) {
	var out Address
	var name, address bool
	err := s.object(func(key string) error {
		var err error
		switch key {
		case "name":
			name = true
			out.Name, err = s.str()
		case "address":
			address = true
			var text string
			if text, err = s.str(); err == nil {
				var ok bool
				if out.Address, ok = hexAddress(text); !ok {
					return s.fail("address %q is not 0x and lower-case hex digits with no leading zero, within 64 bits", text)
				}
			}
		case "type":
			var text string
			if text, err = s.str(); err == nil {
				ref, perr := parseTypeExpression(text)
				if perr != nil {
					return s.fail("%v", perr)
				}
				out.Type = &ref
			}
		default:
			return unknownKey(s, "an address", key)
		}
		return err
	})
	if err == nil && (!name || !address) {
		err = s.fail(`address %q needs "name" and "address"`, out.Name)
	}
	return out, err
}

func hexAddress(text string) (uint64, bool) {
	digits, ok := strings.CutPrefix(text, "0x")
	if !ok || digits == "" || len(digits) > 16 || len(digits) > 1 && digits[0] == '0' {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		switch {
		case '0' <= c && c <= '9':
			v = v<<4 | uint64(c-'0')
		case 'a' <= c && c <= 'f':
			v = v<<4 | uint64(c-'a'+10)
		default:
			return 0, false
		}
	}
	return v, true
}
