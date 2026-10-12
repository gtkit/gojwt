package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/gtkit/gojwt"
)

type entry struct {
	jwk JWK
	key any
}

// Set is an immutable public-key snapshot. Concurrent resolution is safe;
// returned keys and metadata are copies that cannot alter future resolutions.
// Empty kid is an exact key ID, not a fallback for other key IDs.
type Set struct {
	keys    []JWK
	entries map[string]entry
}

var _ gojwt.KeyResolver = (*Set)(nil)

// NewSet validates and copies public keys. Duplicate IDs, including duplicate
// empty IDs, and more than MaxKeys keys are rejected. An empty set is valid.
func NewSet(keys ...JWK) (*Set, error) {
	if len(keys) > MaxKeys {
		return nil, invalid("too many keys")
	}
	set := &Set{keys: make([]JWK, 0, len(keys)), entries: make(map[string]entry, len(keys))}
	for _, j := range keys {
		if _, exists := set.entries[j.KeyID]; exists {
			return nil, invalid("duplicate kid")
		}
		j.KeyOps = slices.Clone(j.KeyOps)
		key, err := j.publicKey()
		if err != nil {
			return nil, err
		}
		set.keys = append(set.keys, j)
		set.entries[j.KeyID] = entry{jwk: j, key: key}
	}
	data, err := set.MarshalJSON()
	if err != nil || len(data) > MaxSetBytes {
		return nil, invalid("encoded key set exceeds size limit")
	}
	return set, nil
}

// Parse decodes a complete public JWKS document. Its JSON must contain a keys
// array, have unique member names and IDs, and satisfy MaxSetBytes / MaxKeys.
// Private parameters (including null values) and symmetric keys are rejected.
func Parse(data []byte) (*Set, error) {
	if len(data) > MaxSetBytes {
		return nil, invalid("key set exceeds size limit")
	}
	if err := checkJSON(data); err != nil {
		return nil, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil || document == nil {
		return nil, invalid("JWKS must be an object")
	}
	rawKeys, exists := document["keys"]
	if !exists {
		return nil, invalid("keys array is missing")
	}
	var encodedKeys []json.RawMessage
	if err := json.Unmarshal(rawKeys, &encodedKeys); err != nil || encodedKeys == nil {
		return nil, invalid("keys must be a non-null array")
	}
	if len(encodedKeys) > MaxKeys {
		return nil, invalid("too many keys")
	}
	keys := make([]JWK, 0, len(encodedKeys))
	for _, encoded := range encodedKeys {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil || fields == nil {
			return nil, invalid("each key must be an object")
		}
		for name := range fields {
			for _, canonical := range []string{"kty", "kid", "alg", "use", "key_ops", "crv", "n", "e", "x", "y", "d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
				if name != canonical && strings.EqualFold(name, canonical) {
					return nil, invalid("reserved JWK parameter names are case-sensitive")
				}
			}
		}
		for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, exists := fields[name]; exists {
				return nil, invalid("private or symmetric key parameters are forbidden")
			}
		}
		for _, name := range []string{"kty", "kid", "alg", "use", "crv", "n", "e", "x", "y"} {
			if raw, present := fields[name]; present {
				var value *string
				if err := json.Unmarshal(raw, &value); err != nil || value == nil {
					return nil, invalid("key parameters must be strings")
				}
			}
		}
		var j JWK
		if err := json.Unmarshal(encoded, &j); err != nil {
			return nil, fmt.Errorf("%w: decode key: %w", ErrInvalidSet, err)
		}
		if _, present := fields["key_ops"]; present && j.KeyOps == nil {
			return nil, invalid("key_ops must be an array permitting verify")
		}
		keys = append(keys, j)
	}
	return NewSet(keys...)
}

// Keys returns independent copies of the public JWK descriptors.
func (s *Set) Keys() []JWK {
	if s == nil {
		return nil
	}
	keys := slices.Clone(s.keys)
	for i := range keys {
		keys[i].KeyOps = slices.Clone(keys[i].KeyOps)
	}
	return keys
}

// MarshalJSON exports only public key material using the standard keys envelope.
func (s *Set) MarshalJSON() ([]byte, error) {
	if s == nil {
		return nil, invalid("nil set")
	}
	keys := s.keys
	if keys == nil {
		keys = []JWK{}
	}
	return json.Marshal(struct {
		Keys []JWK `json:"keys"`
	}{Keys: keys})
}

// ResolveKey returns a copy of the exactly identified public key, provided its
// algorithm, use and key_ops permit verification with the requested algorithm.
func (s *Set) ResolveKey(ctx context.Context, kid, algorithm string) (any, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if s == nil {
		return nil, invalid("nil set")
	}
	e, exists := s.entries[kid]
	if !exists {
		return nil, fmt.Errorf("%w: no matching kid", gojwt.ErrUnknownKeyID)
	}
	if !e.jwk.accepts(algorithm) {
		return nil, ErrAlgorithmMismatch
	}
	return cloneKey(e.key)
}

func cloneKey(key any) (any, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}, nil
	case *ecdsa.PublicKey:
		point, err := key.Bytes()
		if err != nil {
			return nil, invalid("invalid stored EC key")
		}
		return ecdsa.ParseUncompressedPublicKey(key.Curve, point)
	case ed25519.PublicKey:
		return slices.Clone(key), nil
	default:
		return nil, invalid("unsupported stored key")
	}
}
