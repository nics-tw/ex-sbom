package main

import (
	"embed"
	"html/template"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

//go:embed templates/*
var templates embed.FS

func main() {
	r := gin.Default()

	tmpl := template.Must(template.New("").ParseFS(templates, "templates/*"))
	r.SetHTMLTemplate(tmpl)

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r.Run(":" + port)
}
