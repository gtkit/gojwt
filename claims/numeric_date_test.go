package claims

import (
	"encoding/json"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestClaimsNumericDateJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input *jwtv5.NumericDate
		want  string
	}{
		{name: "nil dates"},
		{name: "integer", input: &jwtv5.NumericDate{Time: time.Unix(1700000000, 0)}, want: "1700000000"},
		{name: "fraction", input: &jwtv5.NumericDate{Time: time.Unix(1700000000, 123456789)}, want: "1700000000.123456789"},
		{name: "trim trailing zeros", input: &jwtv5.NumericDate{Time: time.Unix(1, 500000000)}, want: "1.5"},
		{name: "negative integer", input: &jwtv5.NumericDate{Time: time.Unix(-1, 0)}, want: "-1"},
		{name: "negative fraction", input: &jwtv5.NumericDate{Time: time.Unix(-12, 250000000)}, want: "-11.75"},
		{name: "negative nanosecond", input: &jwtv5.NumericDate{Time: time.Unix(0, -1)}, want: "-0.000000001"},
		{name: "minimum", input: &jwtv5.NumericDate{Time: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)}, want: "-62135596800"},
		{name: "maximum", input: &jwtv5.NumericDate{Time: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)}, want: "253402300799.999999999"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			precision := jwtv5.TimePrecision
			c := Claims{
				RegisteredClaims: jwtv5.RegisteredClaims{ExpiresAt: tc.input, NotBefore: tc.input, IssuedAt: tc.input},
				AuthTime:         tc.input,
				Ext:              map[string]any{"count": 1},
				Custom:           map[string]any{"label": "kept"},
			}
			encoded, err := json.Marshal(c)
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(encoded, &fields))
			for _, name := range []string{"exp", "iat", "nbf", "auth_time"} {
				if tc.input == nil {
					_, present := fields[name]
					require.False(t, present)
					continue
				}
				require.Equal(t, tc.want, string(fields[name]))
			}
			require.Equal(t, `"kept"`, string(fields["label"]))
			require.Equal(t, precision, jwtv5.TimePrecision)
			var decoded Claims
			require.NoError(t, json.Unmarshal(encoded, &decoded))
			// 直接 json.Unmarshal 的 Ext 数值类型保持旧契约，精确 JWT 时间通过 gojwt 解析。
			require.IsType(t, float64(0), decoded.Ext["count"])
		})
	}
}
