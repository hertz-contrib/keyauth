// The MIT License (MIT)
//
// Copyright (c) 2020 Fiber
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// This file may have been modified by CloudWeGo authors. All CloudWeGo
// Modifications are Copyright 2022 CloudWeGo Authors.

package keyauth

import (
	"context"
	"errors"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/savsgio/gotils/strconv"
)

// ErrMissingOrMalformedAPIKey When there is no request of the key thrown ErrMissingOrMalformedAPIKey
var ErrMissingOrMalformedAPIKey = errors.New("missing or malformed API Key")

func New(opts ...Option) app.HandlerFunc {
	cfg := NewOptions(opts...)
	parts := strings.Split(cfg.keyLookup, ":")
	if len(parts) != 2 {
		panic(errors.New("the length of parts should be equal to 2"))
	}
	extractor := KeyFromHeader(parts[1], cfg.authScheme)
	switch parts[0] {
	case "query":
		extractor = KeyFromQuery(parts[1])
	case "form":
		extractor = KeyFromForm(parts[1])
	case "param":
		extractor = KeyFromParam(parts[1])
	case "cookie":
		extractor = KeyFromCookie(parts[1])
	}
	// Return middleware handler
	return func(c context.Context, ctx *app.RequestContext) {
		// Filter request to skip middleware
		if cfg.filterHandler != nil && cfg.filterHandler(c, ctx) {
			ctx.Next(c)
			return
		}
		// Extract and verify key
		key, err := extractor(ctx)
		if err != nil {
			cfg.errorHandler(c, ctx, err)
			return
		}
		valid, err := cfg.validator(c, ctx, key)
		if err == nil && valid {
			ctx.Set(cfg.contextKey, key)
			cfg.successHandler(c, ctx)
			return
		}
		cfg.errorHandler(c, ctx, err)
	}
}

// KeyFromHeader returns a function that extracts api key from the request header.
func KeyFromHeader(header, authScheme string) func(*app.RequestContext) (string, error) {
	return func(c *app.RequestContext) (string, error) {
		auth := strconv.B2S(c.GetHeader(header))
		l := len(authScheme)
		if len(auth) > 0 && l == 0 {
			return auth, nil
		}
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", ErrMissingOrMalformedAPIKey
	}
}

// KeyFromQuery returns a function that extracts api key from the query string.
func KeyFromQuery(param string) func(*app.RequestContext) (string, error) {
	return func(c *app.RequestContext) (string, error) {
		key := c.Query(param)
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}

// KeyFromForm returns a function that extracts api key from the form.
func KeyFromForm(param string) func(*app.RequestContext) (string, error) {
	return func(c *app.RequestContext) (string, error) {
		key := strconv.B2S(c.FormValue(param))
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}

// KeyFromParam returns a function that extracts api key from the url param string.
func KeyFromParam(param string) func(*app.RequestContext) (string, error) {
	return func(c *app.RequestContext) (string, error) {
		key := c.Param(param)
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}

// KeyFromCookie returns a function that extracts api key from the named cookie.
func KeyFromCookie(name string) func(*app.RequestContext) (string, error) {
	return func(c *app.RequestContext) (string, error) {
		key := strconv.B2S(c.Cookie(name))
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}
