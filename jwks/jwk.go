// Package jwks encodes, publishes and resolves bounded sets of public JSON Web Keys.
// Remote endpoints must come from trusted application configuration.
package jwks

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"unicode/utf8"
)

// MaxSetBytes is the maximum encoded size of a public JWK set.
const MaxSetBytes = 1 << 20

// MaxKeys is the maximum number of keys in a set.
const MaxKeys = 128

// Errors classify invalid key sets, configuration, algorithms and fetch failures.
var (
	ErrInvalidSet        = errors.New("jwks: invalid public key set")
	ErrInvalidConfig     = errors.New("jwks: invalid configuration")
	ErrAlgorithmMismatch = errors.New("jwks: incompatible key algorithm")
	ErrFetch             = errors.New("jwks: fetch failed")
)

// JWK describes a public RSA, EC or Ed25519 key. Private and symmetric parameters
// are deliberately absent. Use NewKey to export a Go public key.
type JWK struct {
	KeyType   string   `json:"kty"`
	KeyID     string   `json:"kid,omitempty"`
	Algorithm string   `json:"alg,omitempty"`
	Use       string   `json:"use,omitempty"`
	KeyOps    []string `json:"key_ops,omitempty"`
	Curve     string   `json:"crv,omitempty"`
	N         string   `json:"n,omitempty"`
	E         string   `json:"e,omitempty"`
	X         string   `json:"x,omitempty"`
	Y         string   `json:"y,omitempty"`
}

// NewKey exports supported public key material, bound to kid and an optional alg.
// Empty alg permits every supported signature algorithm compatible with the key.
// RSA modulus sizes from 2048 through 16384 bits are accepted.
func NewKey(kid string, publicKey any, algorithm string) (JWK, error) {
	j := JWK{KeyID: kid, Algorithm: algorithm, Use: "sig", KeyOps: []string{"verify"}}
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.N.Sign() <= 0 || key.E < 3 {
			return JWK{}, invalid("RSA public key is missing")
		}
		j.KeyType = "RSA"
		j.N = encode(key.N.Bytes())
		j.E = encode(big.NewInt(int64(key.E)).Bytes())
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil {
			return JWK{}, invalid("EC public key is missing")
		}
		if key.X == nil || key.Y == nil { //nolint:staticcheck // Go 1.26 Bytes can panic on legacy keys with nil coordinates; reject before calling it.
			return JWK{}, invalid("EC public key coordinates are missing")
		}
		switch key.Curve {
		case elliptic.P256():
			j.Curve = "P-256"
		case elliptic.P384():
			j.Curve = "P-384"
		case elliptic.P521():
			j.Curve = "P-521"
		default:
			return JWK{}, invalid("unsupported EC curve")
		}
		point, err := key.Bytes()
		if err != nil {
			return JWK{}, invalid("invalid EC coordinates")
		}
		size := (len(point) - 1) / 2
		j.KeyType = "EC"
		j.X = encode(point[1 : 1+size])
		j.Y = encode(point[1+size:])
	case ed25519.PublicKey:
		j.KeyType, j.Curve, j.X = "OKP", "Ed25519", encode(key)
	default:
		return JWK{}, invalid("only RSA, EC and Ed25519 public keys may be exported")
	}
	if _, err := j.publicKey(); err != nil {
		return JWK{}, err
	}
	return j, nil
}

func (j JWK) publicKey() (any, error) {
	if j.Use != "" && j.Use != "sig" {
		return nil, invalid("key use must be sig")
	}
	if j.KeyOps != nil && (len(j.KeyOps) != 1 || j.KeyOps[0] != "verify") {
		return nil, invalid("key_ops must permit only verify")
	}
	var key any
	switch j.KeyType {
	case "RSA":
		if j.Curve != "" || j.X != "" || j.Y != "" {
			return nil, invalid("mixed RSA and curve parameters")
		}
		n, err := decodeUInt(j.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeUInt(j.E)
		if err != nil {
			return nil, err
		}
		if n.BitLen() < 2048 || n.BitLen() > 16384 || n.Bit(0) == 0 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > (1<<31)-1 || e.Bit(0) == 0 {
			return nil, invalid("invalid RSA modulus or exponent")
		}
		key = &rsa.PublicKey{N: n, E: int(e.Int64())}
	case "EC":
		if j.N != "" || j.E != "" {
			return nil, invalid("mixed EC and RSA parameters")
		}
		curve, _ := curveAlgorithm(j.Curve)
		if curve == nil {
			return nil, invalid("unsupported EC curve")
		}
		size := (curve.Params().BitSize + 7) / 8
		x, err := decodeFixed(j.X, size)
		if err != nil {
			return nil, err
		}
		y, err := decodeFixed(j.Y, size)
		if err != nil {
			return nil, err
		}
		point := make([]byte, 1+2*size)
		point[0] = 4
		copy(point[1:], x)
		copy(point[1+size:], y)
		publicKey, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, invalid("EC point is not on the named curve")
		}
		key = publicKey
	case "OKP":
		if j.Curve != "Ed25519" || j.N != "" || j.E != "" || j.Y != "" {
			return nil, invalid("invalid Ed25519 parameters")
		}
		x, err := decodeFixed(j.X, ed25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		key = ed25519.PublicKey(x)
	default:
		return nil, invalid("unsupported or symmetric key type")
	}
	if j.Algorithm != "" && !j.accepts(j.Algorithm) {
		return nil, invalid("alg conflicts with key type or curve")
	}
	return key, nil
}

func (j JWK) accepts(algorithm string) bool {
	if j.Algorithm != "" && algorithm != j.Algorithm {
		return false
	}
	switch j.KeyType {
	case "RSA":
		return slices.Contains([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}, algorithm)
	case "EC":
		_, alg := curveAlgorithm(j.Curve)
		return algorithm != "" && alg == algorithm
	case "OKP":
		return j.Curve == "Ed25519" && algorithm == "EdDSA"
	default:
		return false
	}
}

func curveAlgorithm(name string) (elliptic.Curve, string) {
	switch name {
	case "P-256":
		return elliptic.P256(), "ES256"
	case "P-384":
		return elliptic.P384(), "ES384"
	case "P-521":
		return elliptic.P521(), "ES512"
	default:
		return nil, ""
	}
}

func encode(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func decode(value string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(data) == 0 || encode(data) != value {
		return nil, invalid("key parameters must use canonical unpadded base64url")
	}
	return data, nil
}

func decodeUInt(value string) (*big.Int, error) {
	data, err := decode(value)
	if err != nil {
		return nil, err
	}
	if data[0] == 0 {
		return nil, invalid("RSA integers must be positive and minimally encoded")
	}
	return new(big.Int).SetBytes(data), nil
}

func decodeFixed(value string, size int) ([]byte, error) {
	data, err := decode(value)
	if err != nil {
		return nil, err
	}
	if len(data) != size {
		return nil, invalid("curve coordinate has incorrect length")
	}
	return data, nil
}

func invalid(message string) error { return fmt.Errorf("%w: %s", ErrInvalidSet, message) }

// checkJSON rejects ambiguous member names and bounds nesting before decoding.
func checkJSON(data []byte) error {
	if !utf8.Valid(data) {
		return invalid("JSON must use valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := checkJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSet, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid("trailing JSON data")
	}
	return nil
}

func checkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds 32 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := name.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid JSON member name")
			}
			seen[key] = true
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
