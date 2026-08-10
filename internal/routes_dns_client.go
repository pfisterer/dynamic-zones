package app

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/farberg/dynamic-zones/internal/helper"
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

// requireZoneOwner refuses to act on a zone the caller does not own.
//
// The TSIG key in the request is what PowerDNS checks, so this endpoint used to
// authorize on key possession alone — turning the API into an open RFC2136 relay
// that any logged-in user could point at any zone: convenient for probing keys
// against an internal DNS server that is otherwise unreachable from outside, and
// for generating load in someone else's name. Ownership is the same rule the
// zone endpoints apply, so nothing legitimate changes.
func requireZoneOwner(app *AppData, c *gin.Context, user *UserClaims, zone string) bool {
	name := strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if name == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "zone is required"})
		return false
	}
	isOwner, err := app.Storage.IsZoneOwner(user.PreferredUsername, name)
	if err != nil {
		app.Log.Errorf("requireZoneOwner: ownership check failed for zone '%s': %v", name, err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to check zone ownership"})
		return false
	}
	if !isOwner {
		app.Log.Warnf("requireZoneOwner: user '%s' is not an owner of zone '%s'", user.PreferredUsername, name)
		c.JSON(http.StatusForbidden, ErrorResponse{Error: "you are not an owner of this zone"})
		return false
	}
	return true
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

// GetTSIGCredentials extracts and validates TSIG credentials from HTTP headers for AXFR.
// It ensures FQDN formatting for KeyName and KeyAlgorithm.
func GetTSIGCredentials(c *gin.Context) (keyNameFQDN, keyAlgoFQDN, key string, err *ErrorResponse) {
	keyName := strings.TrimSpace(c.GetHeader("X-DNS-Key-Name"))
	keyAlgo := strings.TrimSpace(c.GetHeader("X-DNS-Key-Algorithm"))
	key = strings.TrimSpace(c.GetHeader("X-DNS-Key"))

	if keyName == "" || keyAlgo == "" || key == "" {
		return "", "", "", &ErrorResponse{
			Error: "TSIG headers required: X-DNS-Key-Name, X-DNS-Key-Algorithm, X-DNS-Key",
		}
	}

	// Ensure the TSIG Key Name is Fully Qualified.
	keyNameFQDN = keyName
	if !strings.HasSuffix(keyNameFQDN, ".") {
		keyNameFQDN = keyNameFQDN + "."
	}

	// Ensure the TSIG Algorithm Name is Fully Qualified.
	keyAlgoFQDN = dns.Fqdn(keyAlgo)

	return keyNameFQDN, keyAlgoFQDN, key, nil
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

		if !requireZoneOwner(app, c, user, zone) {
			return
		}

		// Ensure Zone Name is FQDN
		zoneFQDN := dns.Fqdn(zone)

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Infof("🚀 List DNS records called for zone: %s by user: %s", zoneFQDN, user.PreferredUsername)
		app.Log.Debug("-------------------------------------------------------------------------------")

		// Get TSIG credentials from headers
		keyNameFQDN, keyAlgoFQDN, key, tsigErr := GetTSIGCredentials(c)
		if tsigErr != nil {
			app.Log.Error("TSIG headers missing")
			c.JSON(http.StatusBadRequest, tsigErr)
			return
		}

		dnsServer := GetServerAddress(app)

		msg := new(dns.Msg)
		msg.SetAxfr(zoneFQDN)
		msg.SetTsig(keyNameFQDN, keyAlgoFQDN, 300, time.Now().Unix())

		tr := new(dns.Transfer)
		tr.TsigSecret = map[string]string{keyNameFQDN: key}

		app.Log.Debugf("Sending AXFR request to DNS server %s for zone %s", dnsServer, zoneFQDN)

		envChan, err := tr.In(msg, dnsServer)
		if err != nil {
			app.Log.Errorf("Error performing AXFR for zone '%s': %v", zoneFQDN, err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}

		var records []DNSRecord

		for env := range envChan {
			if env.Error != nil {
				app.Log.Errorf("AXFR environment error for zone '%s': %v", zoneFQDN, env.Error)
				c.JSON(http.StatusInternalServerError, ErrorResponse{Error: env.Error.Error()})
				return
			}

			for _, rr := range env.RR {
				h := rr.Header()

				if h.Rrtype == dns.TypeSOA ||
					h.Rrtype == dns.TypeRRSIG ||
					h.Rrtype == dns.TypeDNSKEY {
					continue
				}

				var recordValue string
				switch t := rr.(type) {
				case *dns.A:
					recordValue = t.A.String()
				case *dns.AAAA:
					recordValue = t.AAAA.String()
				case *dns.CNAME:
					recordValue = t.Target
				case *dns.NS:
					recordValue = t.Ns
				case *dns.MX:
					// MX records need both the preference and the target
					recordValue = fmt.Sprintf("%d %s", t.Preference, t.Mx)
				case *dns.TXT:
					// TXT records have multiple strings in the slice 'Txt'
					recordValue = strings.Join(t.Txt, " ")
				default:
					// Fallback for types not explicitly handled
					recordValue = rr.String()
				}

				// The name of the record should be normalized if it's the zone apex
				recordName := h.Name

				if h.Name == zoneFQDN || strings.Trim(h.Name, ".") == strings.Trim(zoneFQDN, ".") {
					// For the apex record, use the consistently FQDN version
					recordName = zoneFQDN
				} else if strings.HasPrefix(h.Name, `\@`) {
					// If the name starts with the escaped apex, replace it with the FQDN apex.
					recordName = zoneFQDN
				}
				records = append(records, DNSRecord{
					Zone:  zoneFQDN,
					Name:  recordName,
					Type:  dns.TypeToString[h.Rrtype],
					TTL:   h.Ttl,
					Value: recordValue,
				})
			}
		}

		// Dump all records for debugging
		for _, rec := range records {
			app.Log.Debugf("Retrieved record: Zone=%s Name=%s Type=%s TTL=%d Value=%s",
				rec.Zone, rec.Name, rec.Type, rec.TTL, rec.Value)
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
		app.Log.Infof("🚀 Create record called for record %s, zone: %s by user: %s", req.Name, req.Zone, user.PreferredUsername)
		app.Log.Debug("-------------------------------------------------------------------------------")

		if tsigErr := CheckTSIGRequestData(&req); tsigErr != nil {
			c.JSON(http.StatusBadRequest, tsigErr)
			return
		}

		if !requireZoneOwner(app, c, user, req.Zone) {
			return
		}

		zone := dns.Fqdn(req.Zone)
		name := canonicalRecordName(req.Name, req.Zone)
		dnsServer := GetServerAddress(app)

		// UPSERT = delete first, then add
		switch strings.ToUpper(req.Type) {
		case "A":
			_, _ = helper.Rfc2136DeleteARecord(req.KeyName, req.KeyAlgorithm, req.Key, dnsServer, zone, name)
			_, err := helper.Rfc2136AddARecord(req.KeyName, req.KeyAlgorithm, req.Key, dnsServer, zone, name, req.Value, req.TTL)
			if err != nil {
				c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}

		case "AAAA":
			_, _ = helper.Rfc2136DeleteAAAARecord(req.KeyName, req.KeyAlgorithm, req.Key, dnsServer, zone, name)
			_, err := helper.Rfc2136AddAAAARecord(req.KeyName, req.KeyAlgorithm, req.Key, dnsServer, zone, name, req.Value, req.TTL)
			if err != nil {
				c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}

		default:
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "unsupported type (supported: A, AAAA)"})
			return
		}

		// Echo the record, NOT the request: req carries the TSIG key the client
		// sent, and a credential has no business in a response body (or in
		// whatever logs and proxies that body passes through).
		c.JSON(http.StatusCreated, gin.H{
			"status": "ok",
			"action": "upserted",
			"record": DNSRecord{Zone: zone, Name: name, Type: strings.ToUpper(req.Type), TTL: req.TTL, Value: req.Value},
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

		// TSIG check
		if req.KeyName == "" || req.KeyAlgorithm == "" || req.Key == "" {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "TSIG credentials required: key_name, key_algorithm, key",
			})
			return
		}

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Infof("🚀 Delete record called for record %s, zone: %s by user: %s", req.Name, req.Zone, user.PreferredUsername)
		app.Log.Debug("-------------------------------------------------------------------------------")

		if !requireZoneOwner(app, c, user, req.Zone) {
			return
		}

		zone := dns.Fqdn(req.Zone)

		name := canonicalRecordName(req.Name, req.Zone)

		dnsServer := GetServerAddress(app)

		switch strings.ToUpper(req.Type) {
		case "A":
			_, err := helper.Rfc2136DeleteARecord(req.KeyName, req.KeyAlgorithm, req.Key, dnsServer, zone, name)
			if err != nil {
				c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}

		case "AAAA":
			_, err := helper.Rfc2136DeleteAAAARecord(req.KeyName, req.KeyAlgorithm, req.Key, dnsServer, zone, name)
			if err != nil {
				c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
				return
			}

		default:
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "unsupported type (supported: A, AAAA)"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"action": "deleted",
			"record": req,
		})
	}
}
