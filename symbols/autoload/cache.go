package autoload

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
)

var (
	errBodyTooLarge  = errors.New("autoload: pdb download is larger than MaxDownload")
	errCacheMismatch = errors.New("autoload: cached table is not for this build")
)

// A declared length past the bound is refused before any byte is read; an
// undeclared or understated one is caught by reading one byte past the bound.
func readPDBBody(body io.Reader, declared, limit int64) ([]byte, error) {
	if declared > limit {
		return nil, fmt.Errorf("%w: %d bytes declared, %d allowed", errBodyTooLarge, declared, limit)
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("autoload: read pdb download: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes sent", errBodyTooLarge, limit)
	}
	return data, nil
}

// A table that reads but names another build, or holds no symbols, would be
// served for this build and give wrong or no addresses everywhere.
func loadCached(path string, fp *Fingerprint, read symbols.ReadOptions) (*symbols.Table, error) {
	table, err := symbols.ReadFileWith(path, read)
	if err != nil {
		return nil, fmt.Errorf("autoload: read cached table: %w", err)
	}
	if build, named := table.WindowsPDB(); named && (!strings.EqualFold(build.GUID, fp.GUID) || build.Age != fp.Age) {
		return nil, fmt.Errorf("%w: it names %s-%d", errCacheMismatch, build.GUID, build.Age)
	}
	if len(table.TableSymbols()) == 0 {
		return nil, fmt.Errorf("%w: it holds no symbols", errCacheMismatch)
	}
	return table, nil
}
