package app

import (
	"io/fs"
	"net/http"

	"github.com/farberg/dynamic-zones/internal/generated_docs"
	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/gin-gonic/gin"
)

func CreateHomeRoutes(group *gin.RouterGroup, app *AppData) *gin.RouterGroup {

	// Serve index.html
	group.GET("/", func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, helper.IndexHTML)
	})

	// Serve JS client
	subFS, _ := fs.Sub(generated_docs.ClientDist, "client-dist")
	group.StaticFS("/client", http.FS(subFS))

	// Swagger JSON endpoint
	group.GET("/swagger.json", func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		c.String(http.StatusOK, generated_docs.SwaggerJSON)
	})

	// Expose DNS server configuration
	group.GET(("/config.json"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"dns_server_address": app.Config.PowerDns.DnsServerAddress,
			"dns_server_port":    app.Config.PowerDns.DnsServerPort,
			"version":            generated_docs.Version,
			"auth": gin.H{
				"auth_provider": "oidc",
				"issuer_url":    app.Config.WebServer.OIDCIssuerURL,
				"client_id":     app.Config.WebServer.OIDCClientID,
			},
		})
	})

	// Return the group for further use
	return group
}
