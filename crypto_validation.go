package gojwt

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// validateRSAPublicKey 检查 JOSE RSA 参数域及本库的最小强度。
// 私钥参数另由 cloneRSAPrivateKey 和 rsa.PrivateKey.Validate 检查。
func validateRSAPublicKey(key *rsa.PublicKey) error {
	if key == nil || key.N == nil {
		return fmt.Errorf("%w: RSA public key and modulus must not be nil", ErrInvalidKey)
	}
	if key.N.Sign() <= 0 || key.N.Bit(0) == 0 {
		return fmt.Errorf("%w: RSA modulus must be positive and odd", ErrInvalidKey)
	}
	// crypto/rsa 限制 E 至 32 位有符号整数，避免不同平台的 int 宽度改变行为。
	if key.E < 3 || key.E&1 == 0 || key.E > 1<<31-1 {
		return fmt.Errorf("%w: RSA exponent must be odd and between 3 and 2147483647", ErrInvalidKey)
	}
	if bits := key.N.BitLen(); bits < minRSAKeyBits {
		return fmt.Errorf("%w: RSA key must be at least %d bits, got %d", ErrInvalidConfig, minRSAKeyBits, bits)
	}
	return nil
}

// strictPSSSigningMethod 复制 RS/PS 方法并强制 JOSE 参数，绝不修改 jwt/v5 全局实例。
// PS 的签发和验签均使用摘要等长盐；RS 保留 PKCS1-v1_5 行为。
func strictPSSSigningMethod(method jwtv5.SigningMethod) (jwtv5.SigningMethod, error) {
	switch m := method.(type) {
	case *jwtv5.SigningMethodRSA:
		if m == nil {
			return nil, fmt.Errorf("%w: RSA signing method must not be nil", ErrInvalidConfig)
		}
		if !rsaMethodHashMatches(m.Name, m.Hash, false) {
			return nil, fmt.Errorf("%w: unsupported RSA signing method or hash", ErrInvalidConfig)
		}
		copyMethod := *m
		return &copyMethod, nil
	case *jwtv5.SigningMethodRSAPSS:
		if m == nil || m.SigningMethodRSA == nil {
			return nil, fmt.Errorf("%w: RSA-PSS signing method must not be nil", ErrInvalidConfig)
		}
		if !rsaMethodHashMatches(m.Name, m.Hash, true) {
			return nil, fmt.Errorf("%w: unsupported RSA-PSS signing method or hash", ErrInvalidConfig)
		}
		base := *m.SigningMethodRSA
		return &jwtv5.SigningMethodRSAPSS{
			SigningMethodRSA: &base,
			Options:          &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: base.Hash},
			VerifyOptions:    &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: base.Hash},
		}, nil
	default:
		return nil, fmt.Errorf("%w: expected RSA or RSA-PSS signing method", ErrInvalidConfig)
	}
}

func rsaMethodHashMatches(name string, hash crypto.Hash, pss bool) bool {
	if pss {
		switch name {
		case "PS256":
			return hash == crypto.SHA256
		case "PS384":
			return hash == crypto.SHA384
		case "PS512":
			return hash == crypto.SHA512
		default:
			return false
		}
	}
	switch name {
	case "RS256":
		return hash == crypto.SHA256
	case "RS384":
		return hash == crypto.SHA384
	case "RS512":
		return hash == crypto.SHA512
	default:
		return false
	}
}
