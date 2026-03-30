package gojwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateSecureKey 生成随机 HMAC 密钥字符串。
//
// Deprecated: 请使用 GenerateSecureKeyString。
func GenerateSecureKey() (string, error) {
	return GenerateSecureKeyString()
}

// GenerateSecureKeyString 生成 32 字节随机密钥，并以 RawURLBase64 编码返回。
// 适用于 HMAC-SHA256 签名场景。
func GenerateSecureKeyString() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

// GenerateEd25519Keys 生成 Ed25519 密钥对并写入指定路径的 PEM 文件。
// priPath 为私钥文件路径，pubPath 为公钥文件路径。
// 私钥文件权限 0600，公钥文件权限 0644。
func GenerateEd25519Keys(priPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(priPath), 0o700); err != nil {
		return fmt.Errorf("create private key dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(pubPath), 0o755); err != nil {
		return fmt.Errorf("create public key dir: %w", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	priBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateDER,
	}
	if err := os.WriteFile(priPath, pem.EncodeToMemory(priBlock), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}

// generateTokenID 生成 16 字节随机 token ID，以 RawURLBase64 编码返回。
func generateTokenID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
