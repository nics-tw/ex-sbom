package main

import (
	"embed"
	"ex-s/internal/handler"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
)

//go:embed templates/*
var templates embed.FS

//go:embed static/img/favicon.ico
var favicon embed.FS

//go:embed static/img/apple-touch-icon.png
var image embed.FS

//go:embed static/img/apple-touch-icon-precomposed.png
var image2 embed.FS

func main() {
	config := getConfig()
	server := createServer()

	if config.AutoOpenBrowser {
		go func() {
			time.Sleep(500 * time.Millisecond)
			if err := openBrowser(config.URL()); err != nil {
				slog.Error("Failed to open browser", "error", err)
			}
		}()
	}

	startServer(server, config.Port)
}

type Config struct {
	Port            string
	AutoOpenBrowser bool
}

func getConfig() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	return Config{
		Port:            port,
		AutoOpenBrowser: os.Getenv("AUTO_OPEN_BROWSER") != "false",
	}
}

func (c Config) URL() string {
	return "http://localhost:" + c.Port
}

func createServer() *gin.Engine {
	r := gin.Default()
	setupSSR(r)
	handler.SetupRouterGroup(r)
	return r
}

func startServer(r *gin.Engine, port string) {
	r.Run(":" + port)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return nil // Silently fail on unsupported platforms
	}

	return cmd.Start()
}

func setupSSR(r *gin.Engine) {
	tmpl := template.Must(template.New("").ParseFS(templates, "templates/*"))
	r.SetHTMLTemplate(tmpl)

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.GET("/tutorial", func(c *gin.Context) {
		c.HTML(http.StatusOK, "tutorial.html", nil)
	})

	faviconFS, _ := fs.Sub(favicon, "static/img")
	faviconHandler := http.FileServer(http.FS(faviconFS))
	r.GET("/favicon.ico", func(c *gin.Context) {
		faviconHandler.ServeHTTP(c.Writer, c.Request)
	})

	touchIconFS, _ := fs.Sub(image, "static/img")
	touchIconHandler := http.FileServer(http.FS(touchIconFS))
	r.GET("/apple-touch-icon.png", func(c *gin.Context) {
		touchIconHandler.ServeHTTP(c.Writer, c.Request)
	})

	precomposedFS, _ := fs.Sub(image2, "static/img")
	precomposedHandler := http.FileServer(http.FS(precomposedFS))
	r.GET("/apple-touch-icon-precomposed.png", func(c *gin.Context) {
		precomposedHandler.ServeHTTP(c.Writer, c.Request)
	})
}
