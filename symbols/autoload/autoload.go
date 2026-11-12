package autoload

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

var ErrSymbolsUnavailableOffline = errors.New("autoload: symbols not available offline")

type symbolFetcher func(url string) ([]byte, error)

type LoadOptions struct {
	OfflineOnly bool
	CacheDir    string
	ServerURL   string
	HTTPTimeout time.Duration
	MaxDownload int64
	Read        symbols.ReadOptions
	Limits      limits.Limits
	fetch       symbolFetcher
}

// The capture PDBs measured for S32 are at most 11.4 MB; the default bound
// leaves room for larger builds while stopping a plain-HTTP response from
// streaming without end. MSF stream sizes are 32-bit, which sets the ceiling.
const (
	DefaultServerURL   = "http://msdl.microsoft.com/download/symbols"
	DefaultHTTPTimeout = 10 * time.Minute
	DefaultMaxDownload = 512 << 20
	ceilingHTTPTimeout = 24 * time.Hour
	ceilingDownload    = 1 << 32
)

// BuilderVersion names the cache directory of the tables this converter
// writes; it changes whenever the converter's output for a PDB changes.
const BuilderVersion = "10"

func (o LoadOptions) Resolved() (LoadOptions, error) {
	if o.ServerURL == "" {
		o.ServerURL = DefaultServerURL
	}
	u, err := url.Parse(o.ServerURL)
	if err != nil {
		return LoadOptions{}, fmt.Errorf("autoload: ServerURL %q: %w", o.ServerURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return LoadOptions{}, fmt.Errorf("autoload: ServerURL %q: want an http or https URL with a host and no user, query or fragment", o.ServerURL)
	}
	o.ServerURL = strings.TrimRight(o.ServerURL, "/")
	if o.HTTPTimeout, err = bounded("HTTPTimeout", o.HTTPTimeout, DefaultHTTPTimeout, ceilingHTTPTimeout); err != nil {
		return LoadOptions{}, err
	}
	if o.MaxDownload, err = bounded("MaxDownload", o.MaxDownload, DefaultMaxDownload, ceilingDownload); err != nil {
		return LoadOptions{}, err
	}
	if o.Read, err = o.Read.Resolved(); err != nil {
		return LoadOptions{}, fmt.Errorf("autoload: %w", err)
	}
	if o.Limits, err = o.Limits.Resolved(); err != nil {
		return LoadOptions{}, fmt.Errorf("autoload: %w", err)
	}
	return o, nil
}

func bounded[T int64 | time.Duration](name string, v, fallback, ceiling T) (T, error) {
	switch {
	case v < 0:
		return 0, fmt.Errorf("autoload: %s %v is negative", name, v)
	case v == 0:
		return fallback, nil
	case v > ceiling:
		return 0, fmt.Errorf("autoload: %s %v is past its ceiling %v", name, v, ceiling)
	}
	return v, nil
}

type Fingerprint struct {
	PDBName string
	GUID    string
	Age     uint32
}

// The project's notation for a PDB build, shared with symbols.PDBBuild and
// used as a layout key; the age is decimal here, unlike in a symbol-server
// path.
func (f Fingerprint) String() string {
	return f.PDBName + "/" + f.GUID + "-" + strconv.FormatUint(uint64(f.Age), 10)
}

// SymSrv stores a PDB under <name>/<GUID><age>/<name>, the GUID in 32
// hexadecimal digits and the age in hexadecimal too; measured on the
// Microsoft server, age 23 is found under "17" and not under "23".
func symbolServerPath(fp *Fingerprint) string {
	return fp.PDBName + "/" + strings.ToUpper(fp.GUID) + strings.ToUpper(strconv.FormatUint(uint64(fp.Age), 16)) + "/" + fp.PDBName
}

func ScanKernel(r memory.MemoryReader, l limits.Limits) (*Fingerprint, error) {
	id, err := IdentifyKernel(r, l)
	if err != nil {
		return nil, err
	}
	fp := id.Fingerprint
	return &fp, nil
}

// The NT kernel ships as one of four images, by processor count and by PAE
// on x86, and each image's PDB is named after it.
var kernelPDBNames = []string{"ntoskrnl.pdb", "ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb"}

func IsKernelPDB(name string) bool { return isKernelPDB(name) }

func isKernelPDB(name string) bool {
	for _, k := range kernelPDBNames {
		if strings.EqualFold(name, k) {
			return true
		}
	}
	return false
}

func FormatGUID(b []byte) string { return formatGUID(b) }

// A GUID is stored as a little-endian uint32, two little-endian uint16 and
// eight bytes in order, and written as their hexadecimal digits in that order.
func formatGUID(b []byte) string {
	var out [32]byte
	digits := "0123456789ABCDEF"
	put := func(at int, v uint64, n int) {
		for i := n - 1; i >= 0; i-- {
			out[at+i] = digits[v&0xf]
			v >>= 4
		}
	}
	put(0, uint64(binary.LittleEndian.Uint32(b[0:])), 8)
	put(8, uint64(binary.LittleEndian.Uint16(b[4:])), 4)
	put(12, uint64(binary.LittleEndian.Uint16(b[6:])), 4)
	for i := range 8 {
		put(16+2*i, uint64(b[8+i]), 2)
	}
	return string(out[:])
}

func CacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("autoload: user cache directory: %w", err)
	}
	dir := filepath.Join(base, "libvapour", "symbols", "windows")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("autoload: create symbol cache directory %s: %w", dir, err)
	}
	return dir, nil
}

// The image supplies the fingerprint, which then becomes part of a file path
// and a URL path, so it is held to a bare file name and 32 hex digits.
func validFingerprint(fp *Fingerprint) error {
	const nameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-+~"
	switch {
	case fp == nil:
		return errors.New("autoload: no PDB fingerprint")
	case len(fp.GUID) != 32 || strings.Trim(fp.GUID, "0123456789abcdefABCDEF") != "":
		return fmt.Errorf("autoload: PDB GUID %q is not 32 hex digits", fp.GUID)
	case fp.PDBName == "" || fp.PDBName == "." || fp.PDBName == ".." || strings.Trim(fp.PDBName, nameChars) != "":
		return fmt.Errorf("autoload: PDB name %q is not a file name of letters, digits and ._-+~", fp.PDBName)
	}
	return nil
}

func CachePath(dir string, fp *Fingerprint) (string, error) {
	if err := validFingerprint(fp); err != nil {
		return "", err
	}
	stem := fp.PDBName
	if strings.EqualFold(filepath.Ext(stem), ".pdb") {
		stem = stem[:len(stem)-len(".pdb")]
	}
	name := stem + "-" + strings.ToUpper(fp.GUID) + "-" + strconv.FormatUint(uint64(fp.Age), 10) + ".vsym"
	return filepath.Join(dir, BuilderVersion, name), nil
}

func LoadWithOptions(fp *Fingerprint, opts LoadOptions) (symbols.SymbolTable, error) {
	opts, err := opts.Resolved()
	if err != nil {
		return nil, err
	}
	dir := opts.CacheDir
	if dir == "" {
		if dir, err = CacheDir(); err != nil {
			return nil, err
		}
	}
	path, err := CachePath(dir, fp)
	if err != nil {
		return nil, fmt.Errorf("autoload: symbols for %s: %w", fp, err)
	}

	var rejected error
	if _, statErr := os.Stat(path); statErr == nil {
		table, err := loadCached(path, fp, opts.Read)
		if err == nil {
			return table, nil
		}
		rejected = fmt.Errorf("cached table %s cannot be used: %w", path, err)
	}
	if opts.OfflineOnly {
		if rejected != nil {
			return nil, fmt.Errorf("%w: %s: %v; replace it with a table for this build, or allow network access once to rebuild it",
				ErrSymbolsUnavailableOffline, fp, rejected)
		}
		return nil, fmt.Errorf("%w: %s: no cached table at %s; place a table for this build there, or allow network access once to build it",
			ErrSymbolsUnavailableOffline, fp, path)
	}

	fetch := opts.fetch
	if fetch == nil {
		fetch = httpFetcher(opts.HTTPTimeout, opts.MaxDownload)
	}
	location := opts.ServerURL + "/" + symbolServerPath(fp)
	if err := convertAndCache(fetch, location, path, fp, opts.Limits.Effective().MaxRecursionDepth); err != nil {
		if rejected != nil {
			err = fmt.Errorf("%w; %v", err, rejected)
		}
		return nil, fmt.Errorf("autoload: symbols for %s: %w; supply a symbol table for this build instead", fp, err)
	}
	return symbols.ReadFileWith(path, opts.Read)
}

func AutoLoadWithOptions(r memory.MemoryReader, opts LoadOptions) (symbols.SymbolTable, error) {
	opts, err := opts.Resolved()
	if err != nil {
		return nil, err
	}
	fp, err := ScanKernel(r, opts.Limits)
	if err != nil {
		return nil, err
	}
	return LoadWithOptions(fp, opts)
}

func convertAndCache(fetch symbolFetcher, location, dest string, fp *Fingerprint, maxDepth int) error {
	data, err := fetch(location)
	if err != nil {
		return err
	}
	d, err := pdbToDeclaration(data, fp, maxDepth)
	if err != nil {
		return fmt.Errorf("convert the PDB: %w", err)
	}
	var table bytes.Buffer
	if err := symbols.Encode(&table, d); err != nil {
		return fmt.Errorf("encode the symbol table: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("create symbol cache directory %s: %w", filepath.Dir(dest), err)
	}
	return replaceFile(dest, &table)
}

func httpFetcher(timeout time.Duration, maxDownload int64) symbolFetcher {
	client := &http.Client{Timeout: timeout}
	return func(location string) ([]byte, error) {
		resp, err := client.Get(location) //nolint:noctx // the client carries the timeout
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", location, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("download %s: server answered %s", location, resp.Status)
		}
		data, err := readPDBBody(resp.Body, resp.ContentLength, maxDownload)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", location, err)
		}
		return data, nil
	}
}

// The table is written beside its destination and renamed over it, so a
// reader never sees a partly written cache file.
func replaceFile(dest string, r io.Reader) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), "libvapour-symbols-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return fmt.Errorf("move the table into the cache: %w", err)
	}
	return nil
}
