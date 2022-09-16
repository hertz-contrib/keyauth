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
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/savsgio/gotils/strconv"
)

func TestKeyAuth(t *testing.T) {
	mw := New()
	c := context.Background()
	ctx := app.NewContext(0)
	ctx.Request.SetHeader(consts.HeaderAuthorization, "Bearer valid-key")
	mw(c, ctx)
	token, exist := ctx.Get("token")
	assert.True(t, exist)
	assert.DeepEqual(t, "valid-key", token)
}

func TestKeyAuthWithOptions(t *testing.T) {
	t.Run("WithValidator", func(t *testing.T) {
		mw := New(WithValidator(func(ctx context.Context, requestContext *app.RequestContext, s string) (bool, error) {
			return false, ErrMissingOrMalformedAPIKey
		}))
		c := context.Background()
		ctx := app.NewContext(0)
		ctx.Request.SetHeader(consts.HeaderAuthorization, "Bearer valid-key")
		mw(c, ctx)
		assert.DeepEqual(t, ctx.Response.StatusCode(), http.StatusBadRequest)
		assert.DeepEqual(t, ErrMissingOrMalformedAPIKey.Error(), strconv.B2S(ctx.Response.Body()))
	})

	t.Run("WithErrorHandler", func(t *testing.T) {
		mw := New(WithValidator(func(ctx context.Context, requestContext *app.RequestContext, s string) (bool, error) {
			assert.DeepEqual(t, "valid-key", s)
			return false, ErrMissingOrMalformedAPIKey
		}), WithErrorHandler(func(ctx context.Context, requestContext *app.RequestContext, err error) {
			requestContext.AbortWithMsg("self msg", http.StatusBadRequest)
		}), WithKeyLookUp("param:"+consts.HeaderAuthorization, "Bearer"))

		c := context.Background()
		ctx := app.NewContext(0)
		ctx.Params = append(ctx.Params, param.Param{
			Key:   consts.HeaderAuthorization,
			Value: "valid-key",
		})
		mw(c, ctx)

		assert.DeepEqual(t, ctx.Response.StatusCode(), http.StatusBadRequest)
		assert.DeepEqual(t, "self msg", strconv.B2S(ctx.Response.Body()))
	})

	t.Run("WithLookupQuery", func(t *testing.T) {
		mw := New(WithValidator(func(ctx context.Context, requestContext *app.RequestContext, s string) (bool, error) {
			assert.DeepEqual(t, "valid-key", s)
			return false, ErrMissingOrMalformedAPIKey
		}), WithErrorHandler(func(ctx context.Context, requestContext *app.RequestContext, err error) {
			requestContext.AbortWithMsg("self msg", http.StatusBadRequest)
		}), WithKeyLookUp("query:"+consts.HeaderAuthorization, "Bearer"))

		c := context.Background()
		ctx := app.NewContext(0)
		ctx.Request.SetRequestURI("/ping?Authorization=valid-key")
		mw(c, ctx)

		assert.DeepEqual(t, ctx.Response.StatusCode(), http.StatusBadRequest)
		assert.DeepEqual(t, "self msg", strconv.B2S(ctx.Response.Body()))
	})

	t.Run("WithLookupCookie", func(t *testing.T) {
		mw := New(WithValidator(func(ctx context.Context, requestContext *app.RequestContext, s string) (bool, error) {
			assert.DeepEqual(t, "valid-key", s)
			return false, ErrMissingOrMalformedAPIKey
		}), WithErrorHandler(func(ctx context.Context, requestContext *app.RequestContext, err error) {
			requestContext.AbortWithMsg("self msg", http.StatusBadRequest)
		}), WithKeyLookUp("cookie:"+consts.HeaderAuthorization, "Bearer"))

		c := context.Background()
		ctx := app.NewContext(0)
		ctx.Request.SetCookie(consts.HeaderAuthorization, "valid-key")
		mw(c, ctx)

		assert.DeepEqual(t, ctx.Response.StatusCode(), http.StatusBadRequest)
		assert.DeepEqual(t, "self msg", strconv.B2S(ctx.Response.Body()))
	})

	t.Run("WithLookupForm", func(t *testing.T) {
		mw := New(WithValidator(func(ctx context.Context, requestContext *app.RequestContext, s string) (bool, error) {
			assert.DeepEqual(t, "valid-key", s)
			return false, ErrMissingOrMalformedAPIKey
		}), WithErrorHandler(func(ctx context.Context, requestContext *app.RequestContext, err error) {
			requestContext.AbortWithMsg("self msg", http.StatusBadRequest)
		}), WithKeyLookUp("form:"+consts.HeaderAuthorization, "Bearer"))

		c := context.Background()
		ctx := app.NewContext(0)
		ctx.Request.SetCookie(consts.HeaderAuthorization, "valid-key")
		ctx.Request.SetFormData(map[string]string{consts.HeaderAuthorization: "valid-key"})
		mw(c, ctx)

		assert.DeepEqual(t, ctx.Response.StatusCode(), http.StatusBadRequest)
		assert.DeepEqual(t, "self msg", strconv.B2S(ctx.Response.Body()))
	})
}

func TestDefaultOptions(t *testing.T) {
	opt := NewOptions()
	assert.DeepEqual(t, opt.keyLookup, "header:"+consts.HeaderAuthorization)
	assert.DeepEqual(t, opt.authScheme, "Bearer")
	assert.DeepEqual(t, opt.contextKey, "token")

	opt1 := NewOptions(WithContextKey("token1"),
		WithKeyLookUp("cookie:"+consts.HeaderAuthorization, "bear1"))
	assert.DeepEqual(t, opt1.keyLookup, "cookie:"+consts.HeaderAuthorization)
	assert.DeepEqual(t, opt1.authScheme, "bear1")
	assert.DeepEqual(t, opt1.contextKey, "token1")
}
