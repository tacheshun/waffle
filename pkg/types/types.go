package types

// BlockReason contains information about why a request was blocked
type BlockReason struct {
	Rule    string // Name of the rule that triggered the block
	Message string // Description of why it was blocked
	Wait    int    // For rate limiting, seconds to wait (optional)
}

// TODO: Consider moving other shared types/interfaces here if needed,
// e.g., Rule, Logger, RateLimiter interfaces, to avoid future cycles.
