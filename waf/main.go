package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/corazawaf/coraza/v3"
	"github.com/gin-gonic/gin"
)

type WAFRequest struct {
	Method      string            `json:"method"`
	URI         string            `json:"uri"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	RemoteAddr  string            `json:"remote_addr"`
	ServerAddr  string            `json:"server_addr"`
	ServerPort  int               `json:"server_port"`
}

type WAFResponse struct {
	Allowed     bool   `json:"allowed"`
	StatusCode  int    `json:"status_code,omitempty"`
	Message     string `json:"message,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
	Severity    int    `json:"severity,omitempty"`
}

var wafInstance coraza.WAF

func main() {
	// Initialize Coraza WAF with OWASP CRS
	cfg := coraza.NewWAFConfig().
		WithDirectives(`
		# Basic configuration
		SecRuleEngine On
		SecRequestBodyAccess On
		SecResponseBodyAccess On
		
		# OWASP CRS v4.0 - Base rules
		SecRule REQUEST_HEADERS:User-Agent "@detectSQLi" \
			"id:1001,\
			phase:1,\
			block,\
			msg:'SQL Injection Attack Detected in User-Agent',\
			logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
			tag:'application-multi',\
			tag:'language-multi',\
			tag:'platform-multi',\
			tag:'attack-sqli',\
			tag:'OWASP_CRS',\
			tag:'capec/1000/152/248/66',\
			tag:'PCI/6.5.2',\
			severity:'CRITICAL'"

		SecRule ARGS "@detectXSS" \
			"id:1002,\
			phase:2,\
			block,\
			msg:'XSS Attack Detected',\
			logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
			tag:'application-multi',\
			tag:'language-multi',\
			tag:'platform-multi',\
			tag:'attack-xss',\
			tag:'OWASP_CRS',\
			tag:'capec/1000/152/242/63',\
			tag:'PCI/6.5.7',\
			severity:'CRITICAL'"

		SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "@detectSQLi" \
			"id:1003,\
			phase:2,\
			block,\
			msg:'SQL Injection Attack Detected',\
			logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
			tag:'application-multi',\
			tag:'language-multi',\
			tag:'platform-multi',\
			tag:'attack-sqli',\
			tag:'OWASP_CRS',\
			tag:'capec/1000/152/248/66',\
			tag:'PCI/6.5.2',\
			severity:'CRITICAL'"

		# Path traversal
		SecRule REQUEST_FILENAME|ARGS|REQUEST_HEADERS:Referer "@detectPathTraversal" \
			"id:1004,\
			phase:2,\
			block,\
			msg:'Path Traversal Attack Detected',\
			logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
			tag:'application-multi',\
			tag:'language-multi',\
			tag:'platform-multi',\
			tag:'attack-lfi',\
			tag:'OWASP_CRS',\
			tag:'capec/1000/255/153/126',\
			tag:'PCI/6.5.4',\
			severity:'CRITICAL'"

		# Command injection
		SecRule REQUEST_FILENAME|ARGS|REQUEST_HEADERS "@rx (?i:(?:[;|` + "`" + `]|\\|\\||&&)(?:\\s*(?:(?:s?ftp|https?|ftps?):/{2})?(?:[a-z0-9\\-.]+(?::[a-z0-9\\-.]+)?)?(?:[/@](?:[^?\\s\"')<>\\]}]|(?:(?<=[=:(,])[\"'])|(?:(?<=\\]\\[)[\"']))*)*(?:[?&][^\\s\"'<>\\]]*)?(?:#[^\\s\"'<>\\]]*)?|(?:(?:^|\\W)(?:ftp|https?):\/\/[^\\s]+)))" \
			"id:1005,\
			phase:2,\
			block,\
			msg:'OS Command Injection Attack Detected',\
			logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
			tag:'application-multi',\
			tag:'language-shell',\
			tag:'platform-unix',\
			tag:'attack-injection-generic',\
			tag:'OWASP_CRS',\
			tag:'capec/1000/152/248/88',\
			tag:'PCI/6.5.2',\
			severity:'CRITICAL'"

		# Rate limiting - basic implementation
		SecAction "id:900000,\
			phase:1,\
			nolog,\
			pass,\
			initcol:ip=%{REMOTE_ADDR},\
			setvar:ip.counter=+1,\
			expirevar:ip.counter=60"

		SecRule IP:COUNTER "@gt 100" \
			"id:900001,\
			phase:1,\
			deny,\
			status:429,\
			msg:'Request rate exceeded',\
			logdata:'Client IP: %{REMOTE_ADDR} exceeded 100 requests per minute'"
		`)

	var err error
	wafInstance, err = coraza.NewWAF(cfg)
	if err != nil {
		log.Fatal("Failed to initialize WAF:", err)
	}

	// Set Gin to release mode in production
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// WAF evaluation endpoint
	r.POST("/evaluate", evaluateRequest)

	// Get port from environment or use default
	port := os.Getenv("WAF_PORT")
	if port == "" {
		port = "9000"
	}

	log.Printf("Starting Coraza WAF service on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func evaluateRequest(c *gin.Context) {
	var wafReq WAFRequest
	if err := c.ShouldBindJSON(&wafReq); err != nil {
		c.JSON(http.StatusBadRequest, WAFResponse{
			Allowed: false,
			Message: "Invalid request format: " + err.Error(),
		})
		return
	}

	// Create a new transaction for this request
	tx := wafInstance.NewTransaction()
	defer func() {
		if tx != nil {
			tx.ProcessLogging()
		}
	}()

	// Set connection information
	tx.ProcessConnection(wafReq.RemoteAddr, wafReq.RemoteAddr, wafReq.ServerAddr, wafReq.ServerPort)

	// Process URI
	if it := tx.ProcessURI(wafReq.URI, wafReq.Method, "HTTP/1.1"); it != nil {
		c.JSON(http.StatusForbidden, WAFResponse{
			Allowed:    false,
			StatusCode: it.Status,
			Message:    it.Data,
			RuleID:     fmt.Sprintf("%d", it.RuleID),
		})
		return
	}

	// Process headers
	for name, value := range wafReq.Headers {
		if it := tx.AddRequestHeader(name, value); it != nil {
			c.JSON(http.StatusForbidden, WAFResponse{
				Allowed:    false,
				StatusCode: it.Status,
				Message:    it.Data,
				RuleID:     fmt.Sprintf("%d", it.RuleID),
			})
			return
		}
	}

	// Process request headers phase
	if it := tx.ProcessRequestHeaders(); it != nil {
		c.JSON(http.StatusForbidden, WAFResponse{
			Allowed:    false,
			StatusCode: it.Status,
			Message:    it.Data,
			RuleID:     fmt.Sprintf("%d", it.RuleID),
		})
		return
	}

	// Process request body if present
	if wafReq.Body != "" {
		if it, _, err := tx.WriteRequestBody([]byte(wafReq.Body)); err != nil {
			c.JSON(http.StatusInternalServerError, WAFResponse{
				Allowed: false,
				Message: "Error processing request body: " + err.Error(),
			})
			return
		} else if it != nil {
			c.JSON(http.StatusForbidden, WAFResponse{
				Allowed:    false,
				StatusCode: it.Status,
				Message:    it.Data,
				RuleID:     fmt.Sprintf("%d", it.RuleID),
			})
			return
		}

		// Process request body phase
		if it := tx.ProcessRequestBody(); it != nil {
			c.JSON(http.StatusForbidden, WAFResponse{
				Allowed:    false,
				StatusCode: it.Status,
				Message:    it.Data,
				RuleID:     fmt.Sprintf("%d", it.RuleID),
			})
			return
		}
	}

	// If we reach here, the request is allowed
	c.JSON(http.StatusOK, WAFResponse{
		Allowed: true,
		Message: "Request allowed",
	})
}