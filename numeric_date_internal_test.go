package gojwt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPreciseNumericDateBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    time.Time
		wantErr error
	}{
		{name: "integer", input: "1700000000", want: time.Unix(1700000000, 0)},
		{name: "nanoseconds", input: "1700000000.123456789", want: time.Unix(1700000000, 123456789)},
		{name: "scientific", input: "1.700000000123456789e9", want: time.Unix(1700000000, 123456789)},
		{name: "positive exponent", input: "125e+1", want: time.Unix(1250, 0)},
		{name: "negative exponent", input: "123456789e-9", want: time.Unix(0, 123456789)},
		{name: "negative pre-epoch", input: "-11.75", want: time.Unix(-11, -750000000)},
		{name: "negative nanosecond", input: "-0.000000001", want: time.Unix(0, -1)},
		{name: "negative integer", input: "-1", want: time.Unix(-1, 0)},
		{name: "minimum date", input: "-62135596800", want: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)},
		{name: "maximum date", input: "253402300799.999999999", want: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)},
		{name: "finer than nanoseconds", input: "1.1234567899", want: time.Unix(1, 123456789)},
		{name: "negative fine fraction", input: "-1.1234567899", want: time.Unix(-1, -123456789)},
		{name: "extreme underflow", input: "1e-9223372036854775809", want: time.Unix(0, 0)},
		{name: "bounded underflow", input: "1e-1000000000", want: time.Unix(0, 0)},
		{name: "zero extreme exponent", input: "0e9223372036854775809", want: time.Unix(0, 0)},
		{name: "long canceled exponent", input: "1" + strings.Repeat("0", 10000) + "e-10000", want: time.Unix(1, 0)},
		{name: "empty", wantErr: ErrTokenMalformed},
		{name: "null", input: "null", wantErr: ErrTokenMalformed},
		{name: "quoted", input: `"123"`, wantErr: ErrTokenMalformed},
		{name: "boolean", input: "true", wantErr: ErrTokenMalformed},
		{name: "malformed exponent", input: "1e--2", wantErr: ErrTokenMalformed},
		{name: "int overflow", input: "9223372036854775808", wantErr: ErrTokenMalformed},
		{name: "extreme overflow", input: "1e9223372036854775809", wantErr: ErrTokenMalformed},
		{name: "maximum excluded", input: "253402300800", wantErr: ErrTokenMalformed},
		{name: "before minimum", input: "-62135596800.000000001", wantErr: ErrTokenMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			date, err := parsePreciseNumericDate(json.RawMessage(tc.input))
			require.ErrorIs(t, err, tc.wantErr)
			if tc.wantErr != nil {
				require.Nil(t, date)
				return
			}
			require.True(t, date.Equal(tc.want))
		})
	}
}
