package gojwt

import "time"

type duration struct {
	tokenDuration   time.Duration
	refreshDuration time.Duration
}

type Option func(*duration)
type Options = Option

func WithTokenDuration(t time.Duration) Option {
	return func(d *duration) {
		d.tokenDuration = t
	}
}

func WithRefreshDuration(t time.Duration) Option {
	return func(d *duration) {
		d.refreshDuration = t
	}
}
