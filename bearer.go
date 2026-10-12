package gojwt

import (
	"net/http"
	"strings"
)

// ParseBearerToken 从 Authorization 头的值中取出 Bearer token。
//
// scheme 按 RFC 6750 大小写不敏感，scheme 与 token 之间允许多个空格。
// 头为空返回 ErrAuthorizationMissing（对应 401 并回 WWW-Authenticate），
// scheme 不是 Bearer、token 为空或含空白返回 ErrAuthorizationInvalid（对应 400）。
//
//	token, err := gojwt.ParseBearerToken(r.Header.Get("Authorization"))
func ParseBearerToken(authorization string) (string, error) {
	authorization = strings.Trim(authorization, " ")
	if authorization == "" {
		return "", ErrAuthorizationMissing
	}
	scheme, token, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", ErrAuthorizationInvalid
	}
	token = strings.TrimLeft(token, " ")
	if !validBearerToken(token) {
		return "", ErrAuthorizationInvalid
	}
	return token, nil
}

func validBearerToken(token string) bool {
	if token == "" {
		return false
	}
	padding := false
	characters := 0
	for _, c := range token {
		if c == '=' {
			padding = true
			continue
		}
		if padding {
			return false
		}
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/", c) {
			characters++
			continue
		}
		return false
	}
	return characters > 0
}

// ParseBearerRequest 从请求读取唯一 Authorization 头并提取 Bearer token。
// 缺失或 nil 请求返回 ErrAuthorizationMissing，重复字段和非法字符返回
// ErrAuthorizationInvalid；不从 Cookie、query 或其他位置回落读取凭据。
func ParseBearerRequest(request *http.Request) (string, error) {
	if request == nil {
		return "", ErrAuthorizationMissing
	}
	var values []string
	for key, entries := range request.Header {
		if strings.EqualFold(key, "Authorization") {
			values = append(values, entries...)
		}
	}
	if len(values) == 0 {
		return "", ErrAuthorizationMissing
	}
	if len(values) != 1 {
		return "", ErrAuthorizationInvalid
	}
	return ParseBearerToken(values[0])
}
