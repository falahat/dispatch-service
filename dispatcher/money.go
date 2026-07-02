package dispatcher

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Money is a USD amount in integer cents. Costs and budgets ride the wire as
// decimal-as-strings (the integer-only rule); internally we work in cents so
// arithmetic is exact — no float dollars.
type Money int64

var usdRe = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{2}$`)

// parseUSD converts a decimal-as-string ("12.34") to cents. An empty string is
// zero (an absent cost = free lane). The shape matches the wire pattern.
func parseUSD(s string) (Money, error) {
	if s == "" {
		return 0, nil
	}
	if !usdRe.MatchString(s) {
		return 0, fmt.Errorf("money: %q is not a valid USD amount (NNN.CC)", s)
	}
	dot := strings.IndexByte(s, '.')
	dollars, err := strconv.ParseInt(s[:dot], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("money: %w", err)
	}
	cents, err := strconv.ParseInt(s[dot+1:], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("money: %w", err)
	}
	return Money(dollars*100 + cents), nil
}

// String renders cents back as a decimal-as-string.
func (m Money) String() string {
	neg := ""
	v := int64(m)
	if v < 0 {
		neg, v = "-", -v
	}
	return fmt.Sprintf("%s%d.%02d", neg, v/100, v%100)
}
