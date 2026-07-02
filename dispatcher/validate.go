package dispatcher

import "regexp"

// Shared identifier patterns, matching contracts/schemas/wire.schema.json.
var (
	laneRe    = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	jobIDRe   = regexp.MustCompile(`^j_[0-9A-HJKMNP-TV-Z]{26}$`)
	leaseIDRe = regexp.MustCompile(`^l_[0-9A-HJKMNP-TV-Z]{26}$`)
)
