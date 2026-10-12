package claims_test

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"

	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func TestWithExt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input map[string]any
		key   string
		value any
		want  map[string]any
	}{
		{
			name:  "initialize nil map",
			key:   "tenant_id",
			value: int64(42),
			want:  map[string]any{"tenant_id": int64(42)},
		},
		{
			name:  "write empty map",
			input: map[string]any{},
			key:   "device_id",
			value: "device-1",
			want:  map[string]any{"device_id": "device-1"},
		},
		{
			name:  "preserve other fields",
			input: map[string]any{"tenant_id": int64(42)},
			key:   "device_id",
			value: "device-1",
			want:  map[string]any{"tenant_id": int64(42), "device_id": "device-1"},
		},
		{
			name:  "overwrite existing field",
			input: map[string]any{"device_id": "old", "tenant_id": int64(42)},
			key:   "device_id",
			value: "new",
			want:  map[string]any{"device_id": "new", "tenant_id": int64(42)},
		},
		{
			name:  "write nil value",
			key:   "device_id",
			value: nil,
			want:  map[string]any{"device_id": nil},
		},
		{
			name:  "empty key is retained",
			key:   "",
			value: "empty-key-value",
			want:  map[string]any{"": "empty-key-value"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &claims.Claims{Ext: tt.input}
			claims.WithExt(tt.key, tt.value)(c)
			require.Equal(t, tt.want, c.Ext)
		})
	}
}

func TestClaimsExtString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input map[string]any
		want  string
		ok    bool
	}{
		{name: "nil map"},
		{name: "missing key", input: map[string]any{"other": "value"}},
		{name: "string", input: map[string]any{"value": "device-1"}, want: "device-1", ok: true},
		{name: "empty string", input: map[string]any{"value": ""}, ok: true},
		{name: "nil value", input: map[string]any{"value": nil}},
		{name: "integer is not coerced", input: map[string]any{"value": int64(42)}},
		{name: "bytes are not coerced", input: map[string]any{"value": []byte("device-1")}},
		{name: "boolean is not coerced", input: map[string]any{"value": true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := claims.Claims{Ext: tt.input}
			got, ok := c.ExtString("value")
			require.Equal(t, tt.ok, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsExtInt64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input map[string]any
		want  int64
		ok    bool
	}{
		{name: "nil map"},
		{name: "missing key", input: map[string]any{"other": int64(42)}},
		{name: "nil value", input: map[string]any{"value": nil}},
		{name: "int", input: map[string]any{"value": int(42)}, want: 42, ok: true},
		{name: "negative int", input: map[string]any{"value": int(-42)}, want: -42, ok: true},
		{name: "zero int", input: map[string]any{"value": int(0)}, ok: true},
		{name: "maximum int64", input: map[string]any{"value": int64(math.MaxInt64)}, want: math.MaxInt64, ok: true},
		{name: "minimum int64", input: map[string]any{"value": int64(math.MinInt64)}, want: math.MinInt64, ok: true},
		{name: "float integer", input: map[string]any{"value": float64(42)}, want: 42, ok: true},
		{name: "float zero", input: map[string]any{"value": float64(0)}, ok: true},
		{name: "negative float integer", input: map[string]any{"value": float64(-42)}, want: -42, ok: true},
		{name: "minimum float integer", input: map[string]any{"value": float64(math.MinInt64)}, want: math.MinInt64, ok: true},
		{name: "largest in range float", input: map[string]any{"value": math.Nextafter(float64(math.MaxInt64), math.Inf(-1))}, want: 9223372036854774784, ok: true},
		{name: "positive fractional float", input: map[string]any{"value": 42.5}},
		{name: "negative fractional float", input: map[string]any{"value": -42.5}},
		{name: "NaN", input: map[string]any{"value": math.NaN()}},
		{name: "positive infinity", input: map[string]any{"value": math.Inf(1)}},
		{name: "negative infinity", input: map[string]any{"value": math.Inf(-1)}},
		{name: "float two to power 63", input: map[string]any{"value": math.Exp2(63)}},
		{name: "float below minimum", input: map[string]any{"value": math.Nextafter(float64(math.MinInt64), math.Inf(-1))}},
		{name: "json number", input: map[string]any{"value": json.Number("42")}, want: 42, ok: true},
		{name: "maximum json number", input: map[string]any{"value": json.Number("9223372036854775807")}, want: math.MaxInt64, ok: true},
		{name: "minimum json number", input: map[string]any{"value": json.Number("-9223372036854775808")}, want: math.MinInt64, ok: true},
		{name: "json number above maximum", input: map[string]any{"value": json.Number("9223372036854775808")}},
		{name: "json number below minimum", input: map[string]any{"value": json.Number("-9223372036854775809")}},
		{name: "fractional json number", input: map[string]any{"value": json.Number("42.5")}},
		{name: "invalid json number", input: map[string]any{"value": json.Number("not-a-number")}},
		{name: "empty json number", input: map[string]any{"value": json.Number("")}},
		{name: "numeric string is not coerced", input: map[string]any{"value": "42"}},
		{name: "boolean is not coerced", input: map[string]any{"value": true}},
		{name: "unsigned integer is not coerced", input: map[string]any{"value": uint64(42)}},
		{name: "float32 is not coerced", input: map[string]any{"value": float32(42)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := claims.Claims{Ext: tt.input}
			got, ok := c.ExtInt64("value")
			require.Equal(t, tt.ok, ok)
			if ok {
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func TestClaimsExtJSONRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     any
		useNumber bool
		wantInt   int64
		intOK     bool
		wantStr   string
		stringOK  bool
	}{
		{name: "int becomes readable float64", input: int(42), wantInt: 42, intOK: true},
		{name: "negative int64 becomes readable float64", input: int64(-42), wantInt: -42, intOK: true},
		{name: "minimum int64 survives float decoding", input: int64(math.MinInt64), wantInt: math.MinInt64, intOK: true},
		{name: "rounded maximum int64 is rejected", input: int64(math.MaxInt64)},
		{name: "maximum int64 survives UseNumber", input: int64(math.MaxInt64), useNumber: true, wantInt: math.MaxInt64, intOK: true},
		{name: "minimum int64 survives UseNumber", input: int64(math.MinInt64), useNumber: true, wantInt: math.MinInt64, intOK: true},
		{name: "json number integer", input: json.Number("42"), useNumber: true, wantInt: 42, intOK: true},
		{name: "fraction is rejected", input: 42.5},
		{name: "UseNumber fraction is rejected", input: 42.5, useNumber: true},
		{name: "string stays string", input: "device-1", wantStr: "device-1", stringOK: true},
		{name: "numeric string stays string", input: "42", wantStr: "42", stringOK: true},
		{name: "boolean remains type mismatch", input: true},
		{name: "nil remains type mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			original := &claims.Claims{}
			claims.WithExt("value", tt.input)(original)
			encoded, err := json.Marshal(original)
			require.NoError(t, err)

			decoder := json.NewDecoder(bytes.NewReader(encoded))
			if tt.useNumber {
				decoder.UseNumber()
			}
			var decoded claims.Claims
			require.NoError(t, decoder.Decode(&decoded))

			gotInt, intOK := decoded.ExtInt64("value")
			require.Equal(t, tt.intOK, intOK)
			if intOK {
				require.Equal(t, tt.wantInt, gotInt)
			}
			gotStr, stringOK := decoded.ExtString("value")
			require.Equal(t, tt.stringOK, stringOK)
			require.Equal(t, tt.wantStr, gotStr)
		})
	}
}
