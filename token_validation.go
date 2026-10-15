package gojwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// MaxTokenBytes 是 JWT 解析和 header 选键入口接受的最大字节数（64 KiB）。
// 限制在解码或查找密钥前执行，避免超大外部输入占用内存或触发出站请求。
const MaxTokenBytes = 64 * 1024

// 与常用 RFC 3339 日历范围一致，避免 time.Unix 的内部 epoch 在 int64 边界溢出。
const (
	minNumericDate = -62135596800 // 0001-01-01T00:00:00Z
	maxNumericDate = 253402300800 // 10000-01-01T00:00:00Z，排除上界
)

func validationOptions(cfg *config, opts []jwtv5.ParserOption) []jwtv5.ParserOption {
	result := []jwtv5.ParserOption{jwtv5.WithLeeway(cfg.parseLeeway)}
	result = append(result, cfg.parserOptions...)
	result = append(result, opts...)
	return append(result, jwtv5.WithExpirationRequired(), jwtv5.WithIssuedAt())
}

// decodeTokenObject 拒绝重复成员和尾随 JSON，避免多个解析器对同一载荷得出不同结果。
func decodeTokenObject(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, fmt.Errorf("JSON must be an object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := name.(string)
		if !ok {
			return nil, fmt.Errorf("member name must be a string")
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate member %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return fields, nil
}

func readTokenHeader(raw string) (map[string]json.RawMessage, error) {
	if len(raw) > MaxTokenBytes {
		return nil, fmt.Errorf("%w: token exceeds %d bytes", ErrTokenMalformed, MaxTokenBytes)
	}
	if strings.ContainsAny(raw, "\r\n") {
		return nil, fmt.Errorf("%w: base64url segments must not contain line breaks", ErrTokenMalformed)
	}
	segment, _, found := strings.Cut(raw, ".")
	if !found || segment == "" {
		return nil, ErrTokenMalformed
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding: %w", ErrTokenMalformed, err)
	}
	header, err := decodeTokenObject(data)
	if err != nil {
		return nil, fmt.Errorf("%w: header JSON: %w", ErrTokenMalformed, err)
	}
	// 没有实现任何 critical 扩展，也不支持未编码 payload 的 JWS。
	if _, ok := header["crit"]; ok {
		return nil, fmt.Errorf("%w: critical header extensions are unsupported", ErrTokenUnverifiable)
	}
	if _, ok := header["b64"]; ok {
		return nil, fmt.Errorf("%w: b64 header extension is unsupported", ErrTokenUnverifiable)
	}
	return header, nil
}

// validateTokenPayload 检查完整 payload；WithJSONNumber 的外层 decoder
// 只会把首个 JSON 值交给 UnmarshalJSON，不能依赖后者检查尾随数据。
func validateTokenPayload(raw string, options []jwtv5.ParserOption) error {
	_, tail, ok := strings.Cut(raw, ".")
	if !ok {
		return ErrTokenMalformed
	}
	segment, _, ok := strings.Cut(tail, ".")
	if !ok {
		return ErrTokenMalformed
	}
	data, err := jwtv5.NewParser(options...).DecodeSegment(segment)
	if err != nil {
		return fmt.Errorf("%w: payload encoding: %w", ErrTokenMalformed, err)
	}
	if !json.Valid(data) || !utf8.Valid(data) {
		return fmt.Errorf("%w: payload must be one valid UTF-8 JSON value", ErrTokenMalformed)
	}
	return nil
}

type strictTokenClaims struct {
	*claims.Claims
	allowNumericSubject bool
}

func (c *strictTokenClaims) UnmarshalJSON(data []byte) error {
	fields, err := decodeTokenObject(data)
	if err != nil {
		return err
	}
	for name := range fields {
		if !claims.IsReservedName(name) {
			continue
		}
		// 内置 JSON 字段均为小写 ASCII；拒绝 encoding/json 的大小写及 Unicode 别名。
		for _, char := range name {
			if (char < 'a' || char > 'z') && char != '_' {
				return fmt.Errorf("reserved claim %q is case-sensitive", name)
			}
		}
	}
	for _, name := range []string{"exp", "nbf", "iat", "auth_time"} {
		raw, exists := fields[name]
		if !exists || bytes.Equal(raw, []byte("null")) {
			continue
		}
		if len(raw) == 0 || raw[0] == '"' {
			return fmt.Errorf("%s must be a JSON number", name)
		}
		var number json.Number
		if err := json.Unmarshal(raw, &number); err != nil {
			return fmt.Errorf("%s must be a JSON number: %w", name, err)
		}
		seconds, err := number.Float64()
		// 精确范围在恢复纳秒日期后检查；Float64 可能把年 9999 的最后一纳秒舍入至上界。
		if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds > maxNumericDate || seconds < minNumericDate {
			return fmt.Errorf("%s is outside the supported NumericDate range", name)
		}
	}
	if value, exists := fields["sub"]; exists {
		var subject string
		if err := json.Unmarshal(value, &subject); err != nil || bytes.Equal(value, []byte("null")) {
			if !c.allowNumericSubject {
				return fmt.Errorf("subject must be a string")
			}
			var number json.Number
			if err := json.Unmarshal(value, &number); err != nil {
				return fmt.Errorf("subject must be a string or integer: %w", err)
			}
			text := number.String()
			if strings.ContainsAny(text, ".eE") {
				return fmt.Errorf("subject must be an integer")
			}
			if _, ok := new(big.Int).SetString(text, 10); !ok {
				return fmt.Errorf("subject must be an integer")
			}
			fields["sub"], err = json.Marshal(text)
			if err != nil {
				return err
			}
			data, err = json.Marshal(fields)
			if err != nil {
				return err
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(c.Claims); err != nil {
		return err
	}
	// 上游 NumericDate.UnmarshalJSON 会按全局 TimePrecision 截断，
	// 用已经检查过类型的原始日期恢复精度，不改变 Ext 的 UseNumber 规则。
	for _, field := range []struct {
		name string
		date **jwtv5.NumericDate
	}{
		{name: "exp", date: &c.ExpiresAt},
		{name: "nbf", date: &c.NotBefore},
		{name: "iat", date: &c.IssuedAt},
		{name: "auth_time", date: &c.AuthTime},
	} {
		raw, exists := fields[field.name]
		if !exists || bytes.Equal(raw, []byte("null")) {
			continue
		}
		date, err := parsePreciseNumericDate(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", field.name, err)
		}
		*field.date = date
	}
	for name, raw := range fields {
		if claims.IsReservedName(name) {
			continue
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		if c.Custom == nil {
			c.Custom = make(map[string]any)
		}
		c.Custom[name] = value
	}
	return nil
}

// parsePreciseNumericDate 转换十进制 NumericDate，精度为纳秒；更细的小数向零截断。
// 指数先限定其对小数点的影响，避免极端指数触发整数溢出或巨量补零分配。
func parsePreciseNumericDate(raw json.RawMessage) (*jwtv5.NumericDate, error) {
	var number json.Number
	if len(raw) == 0 || raw[0] == '"' || json.Unmarshal(raw, &number) != nil {
		return nil, fmt.Errorf("%w: NumericDate must be a number", ErrTokenMalformed)
	}
	value := number.String()
	if value == "" {
		return nil, fmt.Errorf("%w: NumericDate must be a number", ErrTokenMalformed)
	}
	negative := strings.HasPrefix(value, "-")
	value = strings.TrimPrefix(value, "-")
	mantissa, exponentText := value, "0"
	if index := strings.IndexAny(value, "eE"); index >= 0 {
		mantissa, exponentText = value[:index], value[index+1:]
	}
	point := len(mantissa)
	if index := strings.IndexByte(mantissa, '.'); index >= 0 {
		point = index
	}
	digits := strings.ReplaceAll(mantissa, ".", "")
	trimmed := strings.TrimLeft(digits, "0")
	point -= len(digits) - len(trimmed)
	digits = trimmed
	if digits == "" {
		return &jwtv5.NumericDate{Time: time.Unix(0, 0).UTC()}, nil
	}
	exponent, err := strconv.ParseInt(exponentText, 10, 64)
	if err != nil {
		if strings.HasPrefix(exponentText, "-") {
			return &jwtv5.NumericDate{Time: time.Unix(0, 0).UTC()}, nil
		}
		return nil, fmt.Errorf("%w: NumericDate exponent is outside the supported range", ErrTokenMalformed)
	}
	if exponent > 19-int64(point) {
		return nil, fmt.Errorf("%w: NumericDate is outside the supported range", ErrTokenMalformed)
	}
	if exponent < -9-int64(point) {
		return &jwtv5.NumericDate{Time: time.Unix(0, 0).UTC()}, nil
	}
	point += int(exponent)
	whole, fraction := "0", ""
	if point > 0 {
		whole = digits[:min(point, len(digits))]
		if point > len(digits) {
			whole += strings.Repeat("0", point-len(digits))
		} else {
			fraction = digits[point:]
		}
	} else {
		fraction = strings.Repeat("0", -point) + digits[:min(9, len(digits))]
	}
	fraction = fraction[:min(9, len(fraction))]
	fraction += strings.Repeat("0", 9-len(fraction))
	if negative {
		whole = "-" + whole
	}
	seconds, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: NumericDate seconds: %w", ErrTokenMalformed, err)
	}
	nanos, err := strconv.ParseInt(fraction, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: NumericDate fraction: %w", ErrTokenMalformed, err)
	}
	if negative {
		nanos = -nanos
	}
	date := time.Unix(seconds, nanos).UTC()
	if date.Year() < 1 || date.Year() > 9999 {
		return nil, fmt.Errorf("%w: NumericDate is outside the supported range", ErrTokenMalformed)
	}
	return &jwtv5.NumericDate{Time: date}, nil
}

// finalizeTokenIdentifiers 只在签名与标准校验成功后归一化撤销标识。
func finalizeTokenIdentifiers(c *claims.Claims) error {
	if c.ID != "" && c.TokenID != "" && c.ID != c.TokenID {
		return fmt.Errorf("%w: jti and token_id disagree", ErrTokenInvalidID)
	}
	if c.TokenID == "" {
		c.TokenID = c.ID
	}
	return nil
}
