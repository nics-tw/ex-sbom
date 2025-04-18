package main

import (
	"embed"
	"ex-s/internal/handler"
	"html/template"
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

func main() {
	r := gin.Default()

	setupSSR(r)
	handler.SetupRouterGroup(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		url := "http://localhost:" + port
		if err := openBrowser(url); err != nil {
			slog.Error("Failed to open browser", "error", err)
		}
	}()

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
}
