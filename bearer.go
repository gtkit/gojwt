package gojwt

import (
	"strings"
	"unicode"
)

// ParseBearerToken 从 Authorization 头的值中取出 Bearer token。
//
// scheme 按 RFC 6750 大小写不敏感，scheme 与 token 之间允许多个空格。
// 头为空返回 ErrAuthorizationMissing（对应 401 并回 WWW-Authenticate），
// scheme 不是 Bearer、token 为空或含空白返回 ErrAuthorizationInvalid（对应 400）。
//
//	token, err := gojwt.ParseBearerToken(r.Header.Get("Authorization"))
func ParseBearerToken(authorization string) (string, error) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return "", ErrAuthorizationMissing
	}
	scheme, token, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", ErrAuthorizationInvalid
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsFunc(token, unicode.IsSpace) {
		return "", ErrAuthorizationInvalid
	}
	return token, nil
}
