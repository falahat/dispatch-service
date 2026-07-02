package wire_test

// ECMAScript regexp engine for JSON Schema validation. The contract schemas use
// ECMA-262 patterns (e.g. the relative_path traversal guard uses negative
// lookahead), which Go's RE2 does not support. JSON Schema mandates ECMA-262,
// so the test tooling must validate faithfully rather than force a weaker
// pattern into the frozen contract. Adapter per the jsonschema/v6 docs.

import (
	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type ecmaRegexp regexp2.Regexp

func (re *ecmaRegexp) MatchString(s string) bool {
	matched, err := (*regexp2.Regexp)(re).MatchString(s)
	return err == nil && matched
}

func (re *ecmaRegexp) String() string { return (*regexp2.Regexp)(re).String() }

func ecmaCompile(s string) (jsonschema.Regexp, error) {
	re, err := regexp2.Compile(s, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	return (*ecmaRegexp)(re), nil
}
