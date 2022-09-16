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
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
)

// Option is the only struct that can be used to set Options.
type Option struct {
	F func(o *Options)
}

type KeyAuthFilterHandler func(c context.Context, ctx *app.RequestContext) bool

type KeyAuthErrorHandler func(context.Context, *app.RequestContext, error)

type KeyAuthValidatorHandler func(context.Context, *app.RequestContext, string) (bool, error)

type Options struct {
	// filterHandler defines a function to skip middleware.
	// Optional. Default: nil
	filterHandler KeyAuthFilterHandler

	// successHandler defines a function which is executed for a valid key.
	// Optional. Default: nil
	successHandler app.HandlerFunc

	// errorHandler defines a function which is executed for an invalid key.
	// It may be used to define a custom error.
	// Optional. Default: 401 Invalid or expired key
	errorHandler KeyAuthErrorHandler

	// keyLookup is a string in the form of "<source>:<name>" that is used
	// to extract key from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "form:<name>"
	// - "param:<name>"
	// - "cookie:<name>"
	keyLookup string

	// authScheme to be used in the Authorization header.
	// Optional. Default value "Bearer".
	authScheme string

	// validator is a function to validate key.
	// Optional. Default: nil
	validator KeyAuthValidatorHandler

	// context key to store the bearertoken from the token into context.
	// Optional. Default: "token".
	contextKey string
}

func (o *Options) Apply(opts []Option) {
	for _, op := range opts {
		op.F(o)
	}
}

func NewOptions(opts ...Option) *Options {
	options := &Options{
		successHandler: func(c context.Context, ctx *app.RequestContext) {
			ctx.Next(c)
		},
		errorHandler: func(c context.Context, ctx *app.RequestContext, err error) {
			if err == ErrMissingOrMalformedAPIKey {
				ctx.AbortWithMsg(err.Error(), http.StatusBadRequest)
				return
			}
			ctx.AbortWithMsg(err.Error(), http.StatusUnauthorized)
		},
		validator: func(ctx context.Context, requestContext *app.RequestContext, s string) (bool, error) {
			return true, nil
		},
		authScheme: "Bearer",
		contextKey: "token",
		keyLookup:  "header:" + consts.HeaderAuthorization,
	}
	options.Apply(opts)
	return options
}

func WithFilter(f KeyAuthFilterHandler) Option {
	return Option{
		F: func(o *Options) {
			o.filterHandler = f
		},
	}
}

func WithSuccessHandler(f app.HandlerFunc) Option {
	return Option{
		F: func(o *Options) {
			o.successHandler = f
		},
	}
}

func WithErrorHandler(f KeyAuthErrorHandler) Option {
	return Option{
		F: func(o *Options) {
			o.errorHandler = f
		},
	}
}

func WithKeyLookUp(lookup, authScheme string) Option {
	return Option{func(o *Options) {
		o.keyLookup = lookup
		o.authScheme = authScheme
	}}
}

func WithValidator(f KeyAuthValidatorHandler) Option {
	return Option{F: func(o *Options) {
		o.validator = f
	}}
}

func WithContextKey(key string) Option {
	return Option{F: func(o *Options) {
		o.contextKey = key
	}}
}
