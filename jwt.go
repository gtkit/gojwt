package gojwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// GenerateSecureKey 生成随机 HMAC 密钥字符串。
//
// Deprecated: 请使用 GenerateHMACKeyString。
func GenerateSecureKey() (string, error) {
	return GenerateHMACKeyString(jwtv5.SigningMethodHS256)
}

// GenerateSecureKeyString 生成 32 字节随机密钥，并以 RawURL base64 编码返回，只满足 HS256 的密钥长度。
//
// Deprecated: 请使用 GenerateHMACKeyString，它按算法生成足够长的密钥。
func GenerateSecureKeyString() (string, error) {
	return GenerateHMACKeyString(jwtv5.SigningMethodHS256)
}

// GenerateHMACKeyString 按算法的最小密钥长度生成随机密钥，以 RawURL base64 字符串返回。
//
// 字符串本身的字节数不小于该算法的最小密钥长度，[]byte(s) 可直接作为 NewJwtHmac 的 secretKey：
// HS256 生成 32 字节随机数（43 字符），HS384 生成 48 字节（64 字符），HS512 生成 64 字节（86 字符）。
// 适合写入配置文件或环境变量。method 为 nil 或不受支持时返回 ErrInvalidConfig。
func GenerateHMACKeyString(method *jwtv5.SigningMethodHMAC) (string, error) {
	resolved, err := resolveHMACSigningMethod(method, true)
	if err != nil {
		return "", err
	}
	key := make([]byte, minHMACKeySize(resolved))
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate HMAC key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

// GenerateEd25519Keys 生成 Ed25519 密钥对并写入指定路径的 PEM 文件。
// priPath 为私钥文件路径（PKCS8 格式），pubPath 为公钥文件路径（PKIX 格式）。
// 私钥文件权限 0600，公钥文件权限 0644。
//
// 文件以独占方式创建：任一目标已存在时返回满足 errors.Is(err, fs.ErrExist) 的错误，
// 已有文件原样保留，本次创建的另一个文件会被删除。调用方可据此在首次部署时生成、后续启动时跳过。
func GenerateEd25519Keys(priPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	return writeKeyPairPEM(priPath, pubPath, priv, pub)
}

// GenerateRSAKeys 生成 RSA 密钥对并写入指定路径的 PEM 文件。
// priPath 为私钥文件路径（PKCS8 格式），pubPath 为公钥文件路径（PKIX 格式）。
// bits 为密钥长度，至少 2048；RS/PS 全系列算法都可用 2048，需要更高安全强度时用 3072 或 4096。
// 私钥文件权限 0600，公钥文件权限 0644。
//
// 文件以独占方式创建：任一目标已存在时返回满足 errors.Is(err, fs.ErrExist) 的错误，
// 已有文件原样保留，本次创建的另一个文件会被删除。
func GenerateRSAKeys(priPath, pubPath string, bits int) error {
	if bits < minRSAKeyBits {
		return fmt.Errorf("%w: RSA key size must be at least %d bits, got %d", ErrInvalidConfig, minRSAKeyBits, bits)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}
	return writeKeyPairPEM(priPath, pubPath, privateKey, &privateKey.PublicKey)
}

// GenerateECDSAKeys 生成 ES256/ES384/ES512 对应曲线的 ECDSA PEM 密钥对。
// algorithm 留空使用 ES256；私钥 PKCS8、0600，公钥 PKIX、0644。
// 不覆盖已有文件；目标存在时保留原文件并返回 fs.ErrExist。
func GenerateECDSAKeys(priPath, pubPath, algorithm string) error {
	if algorithm == "" {
		algorithm = "ES256"
	}
	curve, err := ecdsaCurveForAlgorithm(algorithm)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ECDSA key: %w", err)
	}
	return writeKeyPairPEM(priPath, pubPath, key, &key.PublicKey)
}

// writeKeyPairPEM 把密钥对编码为 PKCS8 / PKIX PEM 并以独占方式写入两个文件。
// 先创建两个文件再写入：第二个文件已存在时删除第一个刚创建的空文件，不留半套密钥。
func writeKeyPairPEM(priPath, pubPath string, privateKey, publicKey any) error {
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(priPath), 0o700); err != nil {
		return fmt.Errorf("create private key dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(pubPath), 0o755); err != nil { // #nosec G301 -- This directory holds public keys; private key directories use 0700.
		return fmt.Errorf("create public key dir: %w", err)
	}

	priFile, err := os.OpenFile(priPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- The caller supplies key paths; request-derived paths must be validated by the application.
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) // #nosec G304 G302 -- Caller-supplied key path; public keys are intentionally readable. Private keys use 0600.
	if err != nil {
		_ = priFile.Close()
		_ = os.Remove(priPath)
		return fmt.Errorf("create public key file: %w", err)
	}

	if err := writeAndClose(priFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})); err != nil {
		_ = pubFile.Close()
		_ = os.Remove(priPath)
		_ = os.Remove(pubPath)
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writeAndClose(pubFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})); err != nil {
		_ = os.Remove(priPath)
		_ = os.Remove(pubPath)
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// writeAndClose 写入并 fsync 后关闭文件；密钥是一次性关键产物，必须确认落盘。
func writeAndClose(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// decodePEMBlock 解码第一个 PEM 块，没有 PEM 块时返回 ErrInvalidKey。
func decodePEMBlock(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidKey)
	}
	return block, nil
}

// parseKeyFile 读取密钥文件并交给对应的 PEM 解析函数，读取失败时保留 fs 错误链并带上路径。
func parseKeyFile[K any](path string, parse func([]byte) (K, error)) (K, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- Key paths come from application configuration; the caller validates request-derived paths.
	if err != nil {
		var zero K
		return zero, fmt.Errorf("read key file %q: %w", path, err)
	}
	return parse(data)
}

// generateTokenID 生成 16 字节随机 token ID，以 RawURLBase64 编码返回。
func generateTokenID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
