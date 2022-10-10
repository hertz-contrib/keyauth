package main

import (
	"context"
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/utils"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/hertz-contrib/keyauth"
)

func main() {
	h := server.Default()
	h.Use(keyauth.New(
		keyauth.WithContextKey("token"),
		keyauth.WithKeyLookUp("query:token", ""),

		// The middleware is skipped when true is returned.
		keyauth.WithFilter(func(c context.Context, ctx *app.RequestContext) bool {
			return true
		}),

		// It may be used to validate key.
		// If returns false or err != nil, then errorHandler is used.
		keyauth.WithValidator(func(ctx context.Context, requestContext *app.RequestContext, s string) (bool, error) {
			return false, keyauth.ErrMissingOrMalformedAPIKey
		}),

		// It may be used to define a custom error.
		keyauth.WithErrorHandler(func(ctx context.Context, requestContext *app.RequestContext, err error) {
			requestContext.AbortWithMsg("msg", http.StatusBadRequest)
		}),
	))
	h.GET("/ping", func(c context.Context, ctx *app.RequestContext) {
		value, _ := ctx.Get("token")
		ctx.JSON(consts.StatusOK, utils.H{"ping": value})
	})
	h.Spin()
}
