package main

import (
	"context"

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
	))
	h.GET("/ping", func(c context.Context, ctx *app.RequestContext) {
		value, _ := ctx.Get("token")
		ctx.JSON(consts.StatusOK, utils.H{"ping": value})
	})
	h.Spin()
}
