package tools

import (
	"fmt"
	"regexp"
)

// RE2 runs in time linear in its input, so an examiner's pattern cannot
// stall a scan of a large image.
func (c Context) PatternOption(key string, ignoreCase bool) (*regexp.Regexp, error) {
	text, err := c.StringOption(key)
	if err != nil || text == "" {
		return nil, err
	}
	source := text
	if ignoreCase {
		source = "(?i)" + text
	}
	re, err := regexp.Compile(source)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is %s; want an RE2 pattern: %v", ErrOptionType, key, describeValue(text), err)
	}
	return re, nil
}
