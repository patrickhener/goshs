//go:build unix

package catcher

import "errors"

var ErrNotFound = errors.New("not found")
