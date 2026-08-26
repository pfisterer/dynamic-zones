package app

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

// ErrorResponse represents a generic API error
type ErrorResponse struct {
	Error string `json:"error"`
}

// Request format for all DNS calls
type DNSRecordRequest struct {
	Zone  string `json:"zone"`
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
	TTL   uint32 `json:"ttl,omitempty"`
	Value string `json:"value,omitempty"`

	KeyName      string `json:"key_name"`
	KeyAlgorithm string `json:"key_algorithm"`
	Key          string `json:"key"`
}

// record is the request without its credentials — what the service operates on.
func (r DNSRecordRequest) record() DNSRecord {
	return DNSRecord{Zone: r.Zone, Name: r.Name, Type: r.Type, TTL: r.TTL, Value: r.Value}
}

// credentials is the other half: the TSIG key the caller supplied. A REST
// client holds the zone's key already, so it sends one; the MCP tools resolve
// theirs with AppData.OwnerTSIG instead of ever seeing it.
func (r DNSRecordRequest) credentials() TSIGCredentials {
	return TSIGCredentials{KeyName: r.KeyName, Algorithm: r.KeyAlgorithm, Key: r.Key}
}

// Response format
type DNSRecord struct {
	Zone  string `json:"zone"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

type DNSRecordsResponse struct {
	Records []DNSRecord `json:"records"`
}

// ------------------------------------
// Register routes
// ------------------------------------
func CreateRfc2136ClientApiGroup(v1 *gin.RouterGroup, app *AppData) *gin.RouterGroup {
	v1.GET("/dns/records", listDNSRecords(app))
	v1.POST("/dns/records/create", createDNSRecord(app))
	v1.POST("/dns/records/delete", deleteDNSRecord(app))

	return v1
}

// canonicalRecordName ensures a record name is fully qualified (FQDN) relative to a zone.
func canonicalRecordName(name, zone string) string {
	zoneFQDN := dns.Fqdn(zone)
	name = strings.TrimSpace(name)

	// Empty or @ means zone apex
	if name == "" || name == "@" {
		return zoneFQDN
	}

	// Already absolute
	if strings.HasSuffix(name, ".") {
		return dns.Fqdn(name)
	}

	// Relative → append zone
	return dns.Fqdn(name + "." + zoneFQDN)
}

// --- New Utility Functions ---

// GetServerAddress returns where THIS service sends its own AXFR and RFC 2136
// traffic. Deliberately not the advertised public address: that one points at
// dnsdist on the node, so every zone transfer used to leave the cluster and come
// back in through the public entrance.
func GetServerAddress(app *AppData) string {
	return app.Config.PowerDns.DnsQueryTarget
}

// GetTSIGCredentials extracts and validates TSIG credentials from HTTP headers
// for AXFR. Qualification of the key name and algorithm is left to the service,
// which has to do it for its own callers anyway.
func GetTSIGCredentials(c *gin.Context) (TSIGCredentials, *ErrorResponse) {
	creds := TSIGCredentials{
		KeyName:   strings.TrimSpace(c.GetHeader("X-DNS-Key-Name")),
		Algorithm: strings.TrimSpace(c.GetHeader("X-DNS-Key-Algorithm")),
		Key:       strings.TrimSpace(c.GetHeader("X-DNS-Key")),
	}
	if !creds.complete() {
		return TSIGCredentials{}, &ErrorResponse{
			Error: "TSIG headers required: X-DNS-Key-Name, X-DNS-Key-Algorithm, X-DNS-Key",
		}
	}
	return creds, nil
}

// CheckTSIGRequestData validates TSIG credentials from a JSON request body for UPDATEs.
func CheckTSIGRequestData(req *DNSRecordRequest) *ErrorResponse {
	if req.KeyName == "" || req.KeyAlgorithm == "" || req.Key == "" {
		return &ErrorResponse{
			Error: "TSIG credentials required: key_name, key_algorithm, key",
		}
	}
	return nil
}

// ------------------------------------
// AXFR — List DNS records
// ------------------------------------

// listDNSRecords godoc
// @Summary List DNS records for a zone
// @Description Returns all DNS records for a given zone. TSIG headers are required.
// @Tags DNS
// @Accept json
// @Produce json
// @Param zone query string true "Zone name"
// @Success 200 {object} DNSRecordsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security ApiKeyAuth
// @ID listDnsRecords
// @Router /v1/dns/records [get]
// listDNSRecords handles an AXFR request for a zone, authenticated via TSIG.
func listDNSRecords(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)

		zone := strings.TrimSpace(c.Query("zone"))
		if zone == "" {
			app.Log.Error("Zone query parameter missing")
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "zone query parameter required"})
			return
		}

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Infof("🚀 List DNS records called for zone: %s by user: %s", zone, user.Identity())
		app.Log.Debug("-------------------------------------------------------------------------------")

		// Get TSIG credentials from headers
		creds, tsigErr := GetTSIGCredentials(c)
		if tsigErr != nil {
			app.Log.Error("TSIG headers missing")
			c.JSON(http.StatusBadRequest, tsigErr)
			return
		}

		records, err := app.RecordsList(c.Request.Context(), user.Identity(), zone, creds)
		if err != nil {
			app.Log.Warnf("listDNSRecords: %v", err)
			c.JSON(StatusOf(err), ErrorResponse{Error: MessageOf(err)})
			return
		}

		c.JSON(http.StatusOK, DNSRecordsResponse{Records: records})
	}
}

// ------------------------------------
// Create DNS Record (RFC2136 UPDATE)
// ------------------------------------

// createDNSRecord godoc
// @Summary Create a DNS record
// @Description Creates a new DNS record in the given zone. TSIG headers required: X-DNS-Key-Name, X-DNS-Key-Algorithm, X-DNS-Key
// @Tags DNS
// @Accept json
// @Produce json
// @Param request body DNSRecordRequest true "DNS record to create"
// @Success 201 {object} DNSRecord "Created record"
// @Failure 400 {object} ErrorResponse "Invalid request or missing TSIG headers"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @ID createDnsRecord
// @Router /v1/dns/records/create [post]
func createDNSRecord(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)

		var req DNSRecordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
			return
		}

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Infof("🚀 Create record called for record %s, zone: %s by user: %s", req.Name, req.Zone, user.Identity())
		app.Log.Debug("-------------------------------------------------------------------------------")

		if tsigErr := CheckTSIGRequestData(&req); tsigErr != nil {
			c.JSON(http.StatusBadRequest, tsigErr)
			return
		}

		record, err := app.RecordUpsert(c.Request.Context(), user.Identity(), req.record(), req.credentials())
		if err != nil {
			app.Log.Warnf("createDNSRecord: %v", err)
			c.JSON(StatusOf(err), ErrorResponse{Error: MessageOf(err)})
			return
		}

		// Echo the record, NOT the request: req carries the TSIG key the client
		// sent, and a credential has no business in a response body (or in
		// whatever logs and proxies that body passes through).
		c.JSON(http.StatusCreated, gin.H{
			"status": "ok",
			"action": "upserted",
			"record": record,
		})
	}
}

// ------------------------------------
// Delete DNS Record (RFC2136 UPDATE)
// ------------------------------------

// deleteDNSRecord godoc
// @Summary Delete a DNS record
// @Description Deletes an existing DNS record from the zone. TSIG headers required: X-DNS-Key-Name, X-DNS-Key-Algorithm, X-DNS-Key
// @Tags DNS
// @Accept json
// @Produce json
// @Param request body DNSRecordRequest true "DNS record to delete"
// @Success 200 {object} DNSRecord "Deleted record"
// @Failure 400 {object} ErrorResponse "Invalid request or missing TSIG headers"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @ID deleteDnsRecord
// @Router /v1/dns/records/delete [post]
func deleteDNSRecord(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)

		var req DNSRecordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request body"})
			return
		}

		if tsigErr := CheckTSIGRequestData(&req); tsigErr != nil {
			c.JSON(http.StatusBadRequest, tsigErr)
			return
		}

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Infof("🚀 Delete record called for record %s, zone: %s by user: %s", req.Name, req.Zone, user.Identity())
		app.Log.Debug("-------------------------------------------------------------------------------")

		record, err := app.RecordDelete(c.Request.Context(), user.Identity(), req.record(), req.credentials())
		if err != nil {
			app.Log.Warnf("deleteDNSRecord: %v", err)
			c.JSON(StatusOf(err), ErrorResponse{Error: MessageOf(err)})
			return
		}

		// The record, not the request: req carries the caller's TSIG key, and
		// echoing it would write a credential into the response body.
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"action": "deleted",
			"record": record,
		})
	}
}
