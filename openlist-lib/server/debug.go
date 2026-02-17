package server

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/cmd/flags"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/OpenListTeam/OpenList/v4/server/middlewares"
	"github.com/gin-gonic/gin"
)

var debugStartAt = time.Now()

func pprofEnabled() bool {
	if flags.Debug || flags.Dev {
		return true
	}
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("OPENLIST_PPROF_ENABLE")))
	return raw == "1" || raw == "true" || raw == "yes"
}

func pprofWindowSeconds() int64 {
	raw := strings.TrimSpace(os.Getenv("OPENLIST_PPROF_WINDOW_SECONDS"))
	if raw == "" {
		return 0
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || secs <= 0 {
		return 0
	}
	return secs
}

func pprofGuard(c *gin.Context) {
	if !pprofEnabled() {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	if window := pprofWindowSeconds(); window > 0 {
		if time.Since(debugStartAt) > time.Duration(window)*time.Second {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}
	if token := strings.TrimSpace(os.Getenv("OPENLIST_PPROF_TOKEN")); token != "" {
		if c.Query("token") != token {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}
	c.Next()
}

func _pprof(g *gin.RouterGroup) {
	g.Use(pprofGuard)
	g.Any("/*name", gin.WrapH(http.DefaultServeMux))
}

func debug(g *gin.RouterGroup) {
	g.GET("/path/*path", middlewares.Down(sign.Verify), func(c *gin.Context) {
		rawPath := c.Request.Context().Value(conf.PathKey).(string)
		c.JSON(200, gin.H{
			"path": rawPath,
		})
	})
	g.GET("/hide_privacy", func(c *gin.Context) {
		common.ErrorStrResp(c, "This is ip: 1.1.1.1", 400)
	})
	g.GET("/gc", func(c *gin.Context) {
		runtime.GC()
		c.String(http.StatusOK, "ok")
	})
	_pprof(g.Group("/pprof"))
}
