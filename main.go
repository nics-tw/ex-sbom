// Copyright (c) 2025 國家資通安全研究院-前瞻研究籌獲中心 National Institute of Cyber Security(RA)
// SPDX-License-Identifier: MIT
// Licensed under the MIT License. See LICENSE file in the project root for license information.

package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"ex-sbom/internal/db"
	"ex-sbom/internal/handler"
	reporthandler "ex-sbom/internal/handler/report"
	sbomhandler "ex-sbom/internal/handler/sbom"
	topohandler "ex-sbom/internal/handler/topology"
	projecthandler "ex-sbom/internal/handler/workspace"
	"ex-sbom/internal/repository"
	ssbom "ex-sbom/internal/service/sbom"
	psvc "ex-sbom/internal/service/workspace"

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

//go:embed static/js
var staticJS embed.FS

const (
	appName    = "ex-sbom"
	dbFileName = "data.duckdb"
	osvAPI     = "https://api.osv.dev/"
)

// defaultDBPath returns the platform-native path for the database file:
//   - macOS：~/Library/Application Support/ex-sbom/data.duckdb
//   - Linux：~/.config/ex-sbom/data.duckdb
//   - Windows：%AppData%\ex-sbom\data.duckdb
func defaultDBPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		slog.Warn("UserConfigDir unavailable, falling back to current directory", "error", err)
		return filepath.Join(".", appName, dbFileName)
	}

	return filepath.Join(configDir, appName, dbFileName)
}

func main() {
	config := getConfig()

	dbDir := filepath.Dir(config.DBPath)
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		slog.Error("Failed to create database directory", "path", dbDir, "error", err)
		os.Exit(1)
	}

	if err := db.Init(config.DBPath); err != nil {
		slog.Error("Failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("LocalDB initialized")

	if err := checkNetworkConnectivity(); err != nil {
		slog.Error("Network check failed", "error", err)
		if runtime.GOOS == "windows" {
			fmt.Println("按 Enter 鍵關閉...")
			fmt.Scanln()
		}
		os.Exit(1)
	}

	// DI wiring
	repo := repository.NewSBOMRepository(db.GormDB)
	cache := ssbom.NewInMemoryCache()
	projectSvc := psvc.New(repo, cache)
	sbomSvc := ssbom.NewService(repo, cache)

	loadInitialData(repo, cache)

	server := createServer(projectSvc, sbomSvc)

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
	DBPath          string
}

func getConfig() Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = defaultDBPath()
	}

	return Config{
		Port:            port,
		AutoOpenBrowser: os.Getenv("AUTO_OPEN_BROWSER") != "false",
		DBPath:          dbPath,
	}
}

func (c Config) URL() string {
	return "http://localhost:" + c.Port
}

func loadInitialData(repo repository.Repository, cache ssbom.Cache) {
	projectID, records, err := repo.GetLatestAll()
	if err != nil {
		slog.Error("Failed to load SBOMs from DB", "error", err)
		return
	}
	for _, rec := range records {
		var formatted ssbom.FormattedSBOM
		if err := json.Unmarshal(rec.BomResult, &formatted); err != nil {
			slog.Error("Failed to unmarshal SBOM from DB", "version", rec.Version, "error", err)
			continue
		}
		cache.Set(projectID, rec.Version, formatted)
		slog.Info("Loaded SBOM from DB", "version", rec.Version)
	}
}

func createServer(projectSvc *psvc.Service, sbomSvc *ssbom.Service) *gin.Engine {
	projectH := projecthandler.New(projectSvc)
	sbomH := sbomhandler.New(sbomSvc, projectSvc)
	topoH := topohandler.New(sbomSvc)
	reportH := reporthandler.New(sbomSvc)

	r := gin.Default()
	setupSSR(r)
	handler.SetupRouterGroup(r, projectH, sbomH, topoH, reportH)

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

// checkNetworkConnectivity verifies that the OSV API is reachable.
// osv-scanner requires internet access to query vulnerability data;
// the program exits if the endpoint is unreachable.
func checkNetworkConnectivity() error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(osvAPI)
	if err != nil {
		return fmt.Errorf("unable to reach %s: %w — osv-scanner requires internet access to query vulnerability data", osvAPI, err)
	}
	defer resp.Body.Close()

	// Only 5xx indicates a real connectivity/availability problem. The OSV API
	// root returns 404 even when healthy, so 4xx must NOT be treated as failure
	// (it would make startup fail on every run). A 5xx means the API itself is
	// degraded and later scans would fail, so we stop early.
	if resp.StatusCode >= 500 {
		return fmt.Errorf("%s returned server error %d — osv-scanner vulnerability data is currently unavailable", osvAPI, resp.StatusCode)
	}

	slog.Info("Network connectivity OK", "endpoint", osvAPI, "status", resp.StatusCode)
	return nil
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

	jsFS, _ := fs.Sub(staticJS, "static/js")
	r.StaticFS("/static/js", http.FS(jsFS))
}
