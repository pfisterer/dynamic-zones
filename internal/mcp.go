package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pfisterer/cloud-self-service-golib/mcpserve"
)

// The MCP endpoint, so an LLM can work with this API on a person's behalf.
//
// It lives IN this service rather than in a server of its own, because one line
// buys everything such a server would have to rebuild: /mcp is mounted with the
// same auth middleware as /v1, and therefore gets token resolution and the
// read-only flag from the same place. A process in front would have to answer
// each of those again, or pass them through and be a hop with no content.
//
// The one thing it does NOT inherit is the read-only rule: for REST, "not a GET"
// stands in for "changes something", which is why RejectWritesForReadOnlyTokens
// sits on the /v1 group. Every MCP call is a POST, reads included, so the tool
// says what it does and the check runs against that — the `mutates` argument to
// mcpserve.AddTool, which is where that rule now lives for both services.
//
// The transport, the per-request server and that gate come from
// github.com/pfisterer/cloud-self-service-golib/mcpserve. What stays here is
// what is about DNS: the tools, their payloads, and who the caller is.
//
// There is no authorization in this file, deliberately: every tool calls the
// same service method the REST handler calls, and those methods own the rules.
// A tool that checked something itself would be a second place for a rule to be
// right or wrong.
//
// One rule this file DOES keep is about secrets. A zone's TSIG key is a
// credential, and a credential handed to a model lands in its context, its
// transcript and its client's storage. No tool returns one — the record tools
// resolve the caller's own key server-side (AppData.OwnerTSIG) and pass it
// straight to PowerDNS, and get_zone answers with the zone's metadata rather
// than the payload the REST route serves the browser.

// mcpCaller is the identity a tool acts as, lifted out of the Gin context and
// into the request context, which is the only thing the SDK hands to the server
// factory.
//
// Who the caller is stays here; mcpserve only ever asks the one question below.
type mcpCaller struct {
	user     *UserClaims
	readOnly bool
}

// ReadOnly satisfies mcpserve.Caller: whether this request's credential may
// change anything. It is the only thing the shared wiring knows about a caller.
func (c mcpCaller) ReadOnly() bool { return c.readOnly }

// RegisterMCPRoutes mounts the MCP endpoint on the given group. The group must
// already carry the authentication middleware and must NOT carry
// RejectWritesForReadOnlyTokens.
func RegisterMCPRoutes(group *gin.RouterGroup, app *AppData) {
	// A server per request, built around the caller: a tool closes over the
	// identity that called it, so there is no way for one request's tools to run
	// with another's rights. That, the transport and the read-only gate are the
	// same in every service doing this and live in the shared library; what is
	// left here is turning a Gin context into a caller.
	handler := mcpserve.Handler(func(caller mcpCaller) *mcp.Server {
		return newMCPServer(app, caller)
	})

	group.Any("", func(c *gin.Context) {
		user, ok := c.MustGet(UserDataKey).(*UserClaims)
		if !ok || user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unable to resolve user context"})
			return
		}
		caller := mcpCaller{user: user, readOnly: IsReadOnlyToken(c)}
		ctx := mcpserve.WithCaller(c.Request.Context(), caller)
		handler.ServeHTTP(c.Writer, c.Request.WithContext(ctx))
	})
}

func newMCPServer(app *AppData, caller mcpCaller) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "dhbw-cloud-dns",
		Title:   "DHBW Cloud — DNS zones and records",
		Version: "1",
	}, nil)

	registerZoneTools(s, app, caller)
	registerRecordTools(s, app, caller)
	registerSharingTools(s, app, caller)
	registerPolicyTools(s, app, caller)
	return s
}

// legacyResult turns the (status, body, error) shape the older app methods
// answer with into an error a tool can return, or nil when the call succeeded.
// The message comes from the body, which is where those methods put the sentence
// meant for a person.
func legacyResult(status int, body any, err error, what string) error {
	if err == nil && status < http.StatusBadRequest {
		return nil
	}
	return fmt.Errorf("%s: %s", what, messageFromBody(body, http.StatusText(status)))
}

// toolErr renders a service error for a model: the message, never the wrapped
// cause, which is for the log.
func toolErr(what string, err error) error {
	return fmt.Errorf("%s: %s", what, MessageOf(err))
}

// ── Tool payloads ───────────────────────────────────────────────────────────

// mcpZone is a zone as a person asks about it. Deliberately not
// ZoneDataResponse: that one carries the TSIG keys.
type mcpZone struct {
	Name string `json:"name" jsonschema:"the zone's fully qualified name"`
	// Exists means the caller manages it: it was created AND they own it. A
	// zone their policy grants but nobody created yet has exists=false, and is
	// what create_zone is for.
	Exists          bool     `json:"exists" jsonschema:"true if the zone exists and the caller owns it"`
	CanJoin         bool     `json:"can_join,omitempty" jsonschema:"the zone exists, sharing is on and the caller may join it as a co-owner"`
	TakenBySomeone  bool     `json:"taken_by_someone_else,omitempty" jsonschema:"someone else created it and sharing is off"`
	AllowSubdomains bool     `json:"allow_subdomains" jsonschema:"whether delegated subzones may be created under it"`
	SharingAllowed  bool     `json:"sharing_allowed" jsonschema:"whether it may be shared with further owners"`
	Parent          string   `json:"parent,omitempty" jsonschema:"for a subzone, the zone it is delegated under"`
	Owners          []string `json:"owners,omitempty" jsonschema:"who manages it; only visible to an owner"`
}

func toMCPZone(z ZoneStatus) mcpZone {
	return mcpZone{
		Name:            z.Name,
		Exists:          z.Exists,
		CanJoin:         z.CanJoin,
		TakenBySomeone:  z.AlreadyTakenBySomeoneElse,
		AllowSubdomains: z.AllowSubdomains,
		SharingAllowed:  z.SharingAllowed,
		Parent:          z.Parent,
		Owners:          z.Owners,
	}
}

type mcpZoneList struct {
	Zones []mcpZone `json:"zones"`
}

type mcpRecord struct {
	Zone  string `json:"zone" jsonschema:"the zone the record belongs to"`
	Name  string `json:"name" jsonschema:"the record's fully qualified name"`
	Type  string `json:"type" jsonschema:"record type, e.g. A or AAAA"`
	TTL   uint32 `json:"ttl" jsonschema:"time to live in seconds"`
	Value string `json:"value" jsonschema:"the record's value, e.g. an IP address"`
}

type mcpRecordList struct {
	Records []mcpRecord `json:"records"`
}

func toMCPRecords(records []DNSRecord) []mcpRecord {
	out := make([]mcpRecord, 0, len(records))
	for _, r := range records {
		out = append(out, mcpRecord{Zone: r.Zone, Name: r.Name, Type: r.Type, TTL: r.TTL, Value: r.Value})
	}
	return out
}

// mcpStatus is the answer of a tool whose result is that it ran. Zone carries
// the name back so a model can quote what it just did.
type mcpStatus struct {
	Status string `json:"status" jsonschema:"ok when the operation went through"`
	Zone   string `json:"zone,omitempty" jsonschema:"the zone that was acted on"`
	Detail string `json:"detail,omitempty" jsonschema:"what happened, in a sentence"`
}

// ── Tool inputs ─────────────────────────────────────────────────────────────

type mcpZoneInput struct {
	Zone string `json:"zone" jsonschema:"the zone's fully qualified name, e.g. me.users.dhbw.site"`
}

type mcpRecordWriteInput struct {
	Zone  string `json:"zone" jsonschema:"the zone to write in; the caller must own it"`
	Name  string `json:"name" jsonschema:"the record name, relative to the zone or fully qualified; @ or empty means the zone apex"`
	Type  string `json:"type" jsonschema:"A or AAAA — the only types this API can write"`
	TTL   uint32 `json:"ttl,omitempty" jsonschema:"time to live in seconds; defaults to 300 when omitted"`
	Value string `json:"value" jsonschema:"the IP address to point at"`
}

type mcpRecordDeleteInput struct {
	Zone string `json:"zone" jsonschema:"the zone to delete from; the caller must own it"`
	Name string `json:"name" jsonschema:"the record name, relative to the zone or fully qualified"`
	Type string `json:"type" jsonschema:"A or AAAA"`
}

// mcpZoneDeleteInput asks for the name twice on purpose — see the note above
// registerZoneTools.
type mcpZoneDeleteInput struct {
	Zone        string `json:"zone" jsonschema:"the zone to delete"`
	ConfirmZone string `json:"confirm_zone" jsonschema:"the zone's exact name again, as a confirmation that this is the right one"`
}

type mcpOwnerInput struct {
	Zone  string `json:"zone" jsonschema:"the zone to change the owners of; the caller must own it"`
	Email string `json:"email" jsonschema:"the co-owner's email address"`
}

type mcpRuleInput struct {
	ZonePattern      string `json:"zone_pattern" jsonschema:"the zone names this rule grants, e.g. %u.users.dhbw.site where %u is the user"`
	ZoneSoa          string `json:"zone_soa" jsonschema:"the base zone this nameserver is authoritative for, e.g. users.dhbw.site"`
	TargetUserFilter string `json:"target_user_filter" jsonschema:"which users it applies to, e.g. *@dhbw.de"`
	AllowSubdomains  bool   `json:"allow_subdomains,omitempty" jsonschema:"let owners create delegated subzones below the granted zone"`
	SharingAllowed   bool   `json:"sharing_allowed,omitempty" jsonschema:"let the granted zone be shared with further owners"`
	Description      string `json:"description,omitempty" jsonschema:"a note about what this rule is for"`
}

type mcpRuleUpdateInput struct {
	ID int64 `json:"id" jsonschema:"id of the rule to change; list_policy_rules shows it"`
	mcpRuleInput
}

type mcpRuleDeleteInput struct {
	ID int64 `json:"id" jsonschema:"id of the rule to delete"`
	// The pattern, not the id, is what a person recognises a rule by — and a
	// wrong rule deleted is zones orphaned for everyone it granted.
	ConfirmZonePattern string `json:"confirm_zone_pattern" jsonschema:"the rule's exact zone_pattern, as a confirmation that this is the right rule"`
}

type mcpDelegationInput struct {
	TargetUserFilter string `json:"target_user_filter" jsonschema:"who is being delegated to, e.g. someone@dhbw.de or *@dhbw.de"`
	ZoneSuffix       string `json:"zone_suffix" jsonschema:"the zone they may manage rules for, including everything below it"`
	Description      string `json:"description,omitempty" jsonschema:"a note about what this delegation is for"`
}

type mcpDelegationUpdateInput struct {
	ID int64 `json:"id" jsonschema:"id of the delegation to change"`
	mcpDelegationInput
}

type mcpDelegationDeleteInput struct {
	ID                int64  `json:"id" jsonschema:"id of the delegation to delete"`
	ConfirmZoneSuffix string `json:"confirm_zone_suffix" jsonschema:"the delegation's exact zone_suffix, as a confirmation"`
}

// ── Zones ───────────────────────────────────────────────────────────────────

// The zone tools. Creating a zone is a write that can be undone by deleting it;
// deleting one cannot be undone — the zone, every record in it and every owner's
// TSIG key are gone, and any external-dns pointing at it stops working.
//
// So delete_zone asks for the name twice. That is NOT a defence against prompt
// injection — injected text can contain a zone name as easily as anything else —
// and it is not sold as one. It catches the likelier failure: a model that
// resolved "delete the old one" to the wrong zone. Echoing the name means it had
// to read the thing first, and it puts the name in front of the person whose
// client is asking them to approve the call.
func registerZoneTools(s *mcp.Server, app *AppData, caller mcpCaller) {
	mcpserve.AddTool(s, caller, false, &mcp.Tool{
		Name: "list_my_zones",
		Description: "List the DNS zones the calling user may use: the ones they already manage, and the ones " +
			"their policy entitles them to create. exists=false means it can be created with create_zone.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, mcpZoneList, error) {
		zones, err := app.ZoneList(caller.user)
		if err != nil {
			return nil, mcpZoneList{}, fmt.Errorf("list zones: %w", err)
		}
		out := make([]mcpZone, 0, len(zones))
		for _, z := range zones {
			out = append(out, toMCPZone(z))
		}
		return nil, mcpZoneList{Zones: out}, nil
	})

	mcpserve.AddTool(s, caller, false, &mcp.Tool{
		Name: "get_zone",
		Description: "Look up one zone: whether it exists, who owns it, whether it may be shared and whether " +
			"subzones may be created under it. Use list_dns_records for its contents.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpZoneInput) (*mcp.CallToolResult, mcpZone, error) {
		zones, err := app.ZoneList(caller.user)
		if err != nil {
			return nil, mcpZone{}, fmt.Errorf("get zone: %w", err)
		}
		want := normalizeZone(in.Zone)
		for _, z := range zones {
			if normalizeZone(z.Name) == want {
				return nil, toMCPZone(z), nil
			}
		}
		return nil, mcpZone{}, fmt.Errorf("no zone %q that you own or are entitled to", in.Zone)
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "create_zone",
		Description: "Create a DNS zone the calling user is entitled to, or a delegated subzone under a zone " +
			"they own that allows subdomains. The zone gets its own TSIG key, which stays on the server.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpZoneInput) (*mcp.CallToolResult, mcpStatus, error) {
		zone := normalizeZone(in.Zone)
		app.Log.Infow("MCP create_zone", "user", caller.user.Identity(), "zone", zone)
		if _, err := app.ZoneCreateAuthorized(ctx, caller.user, zone); err != nil {
			return nil, mcpStatus{}, toolErr("create zone", err)
		}
		return nil, mcpStatus{Status: "ok", Zone: zone, Detail: "zone created"}, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "delete_zone",
		Description: "Delete a zone for ALL its owners. This cannot be undone: every record in it and every " +
			"owner's key are gone, and anything updating it (external-dns, ACME) stops working. Ask the person " +
			"before calling this. To leave a shared zone without deleting it, use remove_zone_owner on yourself.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpZoneDeleteInput) (*mcp.CallToolResult, mcpStatus, error) {
		zone := normalizeZone(in.Zone)
		// Normalized on both sides: a trailing dot is the same zone, and being
		// refused over one would teach a model to retry rather than to check.
		if err := mcpserve.ConfirmEcho("confirm_zone", normalizeZone(in.ConfirmZone), zone, "the zone"); err != nil {
			return nil, mcpStatus{}, err
		}
		app.Log.Infow("MCP delete_zone", "user", caller.user.Identity(), "zone", zone)
		if err := app.ZoneDeleteAuthorized(ctx, caller.user, zone); err != nil {
			return nil, mcpStatus{}, toolErr("delete zone", err)
		}
		return nil, mcpStatus{Status: "ok", Zone: zone, Detail: "zone deleted for all owners"}, nil
	})
}

// ── Records ─────────────────────────────────────────────────────────────────

// The record tools. Every one of them resolves the caller's own TSIG key inside
// the service and hands it to PowerDNS; none of them returns it. That is the
// whole reason RecordsList/RecordUpsert/RecordDelete exist as service methods:
// the REST routes take the key from the request because the browser holds it,
// and a model must not be put in that position.
func registerRecordTools(s *mcp.Server, app *AppData, caller mcpCaller) {
	// withKey runs f with the caller's key for the zone. Resolution failures
	// come back as the service's own message: an owner without a key is a zone
	// in a broken state, not a permissions problem, and the two read differently.
	withKey := func(ctx context.Context, zone string, f func(TSIGCredentials) error) error {
		creds, err := app.OwnerTSIG(ctx, caller.user.Identity(), zone)
		if err != nil {
			return toolErr("resolve the zone key", err)
		}
		return f(creds)
	}

	mcpserve.AddTool(s, caller, false, &mcp.Tool{
		Name: "list_dns_records",
		Description: "List the DNS records of a zone the calling user owns. SOA and DNSSEC records are left " +
			"out; everything else the zone holds is returned.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpZoneInput) (*mcp.CallToolResult, mcpRecordList, error) {
		var out mcpRecordList
		err := withKey(ctx, in.Zone, func(creds TSIGCredentials) error {
			records, err := app.RecordsList(ctx, caller.user.Identity(), in.Zone, creds)
			if err != nil {
				return toolErr("list records", err)
			}
			out = mcpRecordList{Records: toMCPRecords(records)}
			return nil
		})
		return nil, out, err
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "set_dns_record",
		Description: "Create or replace an A or AAAA record in a zone the calling user owns. An existing record " +
			"of the same name and type is overwritten. Those two types are all this API can write.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpRecordWriteInput) (*mcp.CallToolResult, mcpRecord, error) {
		ttl := in.TTL
		if ttl == 0 {
			ttl = 300
		}
		rec := DNSRecord{Zone: in.Zone, Name: in.Name, Type: in.Type, TTL: ttl, Value: in.Value}
		var out mcpRecord
		app.Log.Infow("MCP set_dns_record", "user", caller.user.Identity(),
			"zone", in.Zone, "name", in.Name, "type", in.Type)
		err := withKey(ctx, in.Zone, func(creds TSIGCredentials) error {
			written, err := app.RecordUpsert(ctx, caller.user.Identity(), rec, creds)
			if err != nil {
				return toolErr("set record", err)
			}
			out = mcpRecord{Zone: written.Zone, Name: written.Name, Type: written.Type, TTL: written.TTL, Value: written.Value}
			return nil
		})
		return nil, out, err
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "delete_dns_record",
		Description: "Delete an A or AAAA record from a zone the calling user owns. Deleting a record that is " +
			"not there is not an error.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpRecordDeleteInput) (*mcp.CallToolResult, mcpRecord, error) {
		rec := DNSRecord{Zone: in.Zone, Name: in.Name, Type: in.Type}
		var out mcpRecord
		app.Log.Infow("MCP delete_dns_record", "user", caller.user.Identity(),
			"zone", in.Zone, "name", in.Name, "type", in.Type)
		err := withKey(ctx, in.Zone, func(creds TSIGCredentials) error {
			deleted, err := app.RecordDelete(ctx, caller.user.Identity(), rec, creds)
			if err != nil {
				return toolErr("delete record", err)
			}
			out = mcpRecord{Zone: deleted.Zone, Name: deleted.Name, Type: deleted.Type}
			return nil
		})
		return nil, out, err
	})
}

// ── Sharing ─────────────────────────────────────────────────────────────────

// Who manages a zone. None of these destroys anything: an owner removed can be
// added back, a join can be undone by leaving. Key rotation is the disruptive
// one — every owner has to re-fetch their key and anything holding the old one
// (external-dns, an ACME client) stops until it does — so it says so, but it
// does not lose data and needs no confirmation dance.
func registerSharingTools(s *mcp.Server, app *AppData, caller mcpCaller) {
	mcpserve.AddTool(s, caller, false, &mcp.Tool{
		Name:        "list_zone_owners",
		Description: "List who manages a zone. Only an owner may ask.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpZoneInput) (*mcp.CallToolResult, mcpStatus, error) {
		zone := normalizeZone(in.Zone)
		isOwner, err := app.Storage.IsZoneOwner(caller.user.Identity(), zone)
		if err != nil {
			return nil, mcpStatus{}, fmt.Errorf("check ownership: %w", err)
		}
		if !isOwner {
			return nil, mcpStatus{}, fmt.Errorf("you are not an owner of %q", zone)
		}
		owners, err := app.Storage.ListZoneOwners(zone)
		if err != nil {
			return nil, mcpStatus{}, fmt.Errorf("list owners: %w", err)
		}
		return nil, mcpStatus{Status: "ok", Zone: zone, Detail: strings.Join(owners, ", ")}, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "join_zone",
		Description: "Become a co-owner of an existing zone the calling user is entitled to and that allows " +
			"sharing. list_my_zones marks those with can_join.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpZoneInput) (*mcp.CallToolResult, mcpStatus, error) {
		zone := normalizeZone(in.Zone)
		app.Log.Infow("MCP join_zone", "user", caller.user.Identity(), "zone", zone)
		status, body, err := app.ZoneJoin(ctx, caller.user, zone)
		if err := legacyResult(status, body, err, "join zone"); err != nil {
			return nil, mcpStatus{}, err
		}
		return nil, mcpStatus{Status: "ok", Zone: zone, Detail: "you are now a co-owner"}, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "add_zone_owner",
		Description: "Add someone as a co-owner of a zone. They get their own key and can manage the zone as " +
			"the caller does. Owner-only, and the zone must allow sharing.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpOwnerInput) (*mcp.CallToolResult, mcpStatus, error) {
		zone := normalizeZone(in.Zone)
		app.Log.Infow("MCP add_zone_owner", "user", caller.user.Identity(), "zone", zone, "new_owner", in.Email)
		status, body, err := app.ZoneAddOwner(ctx, caller.user, zone, in.Email)
		if err := legacyResult(status, body, err, "add owner"); err != nil {
			return nil, mcpStatus{}, err
		}
		return nil, mcpStatus{Status: "ok", Zone: zone, Detail: in.Email + " is now a co-owner"}, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "remove_zone_owner",
		Description: "Remove a co-owner from a zone; their key is revoked. The last owner cannot be removed — " +
			"deleting the zone is a separate, destructive act. Pass the caller's own address to leave a shared zone.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpOwnerInput) (*mcp.CallToolResult, mcpStatus, error) {
		zone := normalizeZone(in.Zone)
		app.Log.Infow("MCP remove_zone_owner", "user", caller.user.Identity(), "zone", zone, "owner", in.Email)
		status, body, err := app.ZoneRemoveOwner(ctx, caller.user, zone, in.Email)
		if err := legacyResult(status, body, err, "remove owner"); err != nil {
			return nil, mcpStatus{}, err
		}
		return nil, mcpStatus{Status: "ok", Zone: zone, Detail: in.Email + " no longer manages this zone"}, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "rotate_zone_keys",
		Description: "Replace every owner's TSIG key for a zone, e.g. after one leaked. Disruptive: everything " +
			"using an old key (external-dns, ACME clients) stops updating until it is reconfigured. Nothing is lost.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpZoneInput) (*mcp.CallToolResult, mcpStatus, error) {
		zone := normalizeZone(in.Zone)
		app.Log.Infow("MCP rotate_zone_keys", "user", caller.user.Identity(), "zone", zone)
		status, body, err := app.ZoneRotateKeys(ctx, caller.user, zone)
		if err := legacyResult(status, body, err, "rotate keys"); err != nil {
			return nil, mcpStatus{}, err
		}
		return nil, mcpStatus{Status: "ok", Zone: zone,
			Detail: "keys rotated; every owner must fetch their new key from the web UI"}, nil
	})
}

// ── Policy administration ───────────────────────────────────────────────────

// The admin half: policy rules, delegations, orphaned zones. These are not the
// daily work — they decide who gets which zones at all, and a rule is not a
// record: it is evaluated live, so editing one changes what EVERY matching user
// may do, retroactively.
//
// That is why deleting a rule or a delegation asks for a distinguishing field to
// be echoed back, and why nothing here can delete a zone. A zone that no rule
// covers any more shows up as orphaned — and an orphaned zone is almost always a
// mistyped rule, not garbage: fix the rule and the zone is back. The listing is
// offered so that mistake can be SEEN; the deletion that would make it permanent
// is deliberately not.
func registerPolicyTools(s *mcp.Server, app *AppData, caller mcpCaller) {
	toRuleRequest := func(in mcpRuleInput) PolicyRuleRequest {
		return PolicyRuleRequest{
			ZonePattern:      in.ZonePattern,
			ZoneSoa:          in.ZoneSoa,
			TargetUserFilter: in.TargetUserFilter,
			AllowSubdomains:  in.AllowSubdomains,
			SharingAllowed:   in.SharingAllowed,
			Description:      in.Description,
		}
	}

	// mayManage is the same check the REST handlers apply: super-admin, or a
	// delegation covering that base zone.
	mayManage := func(zoneSoa string) error {
		allowed, err := app.userCanManageZoneSoa(caller.user, zoneSoa)
		if err != nil {
			return fmt.Errorf("check permissions: %w", err)
		}
		if !allowed {
			return fmt.Errorf("you are not allowed to manage rules for %q", zoneSoa)
		}
		return nil
	}

	requireSuperAdmin := func() error {
		if !isSuperAdmin(app, caller.user) {
			return fmt.Errorf("%s", errNotSuperAdmin)
		}
		return nil
	}

	mcpserve.AddTool(s, caller, false, &mcp.Tool{
		Name: "list_policy_rules",
		Description: "List the policy rules that decide which users get which zones. A plain user sees the " +
			"rules that grant them something; an admin sees all of them.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, PolicyRulesResponse, error) {
		rules, err := app.PolicyGetAllUserRules(caller.user)
		if err != nil {
			return nil, PolicyRulesResponse{}, fmt.Errorf("list policy rules: %w", err)
		}
		return nil, *rules, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "create_policy_rule",
		Description: "Create a policy rule granting zones to users. Takes effect immediately for everyone the " +
			"filter matches. Requires being a super-admin or holding a delegation for the base zone.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpRuleInput) (*mcp.CallToolResult, PolicyRule, error) {
		if err := mayManage(in.ZoneSoa); err != nil {
			return nil, PolicyRule{}, err
		}
		app.Log.Infow("MCP create_policy_rule", "user", caller.user.Identity(), "zone_pattern", in.ZonePattern)
		rule, err := app.PolicyCreateRule(toRuleRequest(in))
		if err != nil {
			return nil, PolicyRule{}, fmt.Errorf("create rule: %w", err)
		}
		return nil, *rule, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "update_policy_rule",
		Description: "Change a policy rule. Every field is given in full, not as a delta. A user who loses a " +
			"zone by this keeps nothing: their zone becomes orphaned. Requires rights on both the old and new base zone.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpRuleUpdateInput) (*mcp.CallToolResult, PolicyRule, error) {
		existing, err := app.Storage.PolicyGetByID(in.ID)
		if err != nil {
			return nil, PolicyRule{}, fmt.Errorf("no rule with id %d", in.ID)
		}
		// Both ends, so a rule cannot be moved out of the caller's scope.
		if err := mayManage(existing.ZoneSoa); err != nil {
			return nil, PolicyRule{}, err
		}
		if err := mayManage(in.ZoneSoa); err != nil {
			return nil, PolicyRule{}, err
		}
		app.Log.Infow("MCP update_policy_rule", "user", caller.user.Identity(), "rule_id", in.ID)
		rule, err := app.PolicyUpdateRule(in.ID, toRuleRequest(in.mcpRuleInput))
		if err != nil {
			return nil, PolicyRule{}, fmt.Errorf("update rule %d: %w", in.ID, err)
		}
		return nil, *rule, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "delete_policy_rule",
		Description: "Delete a policy rule. Everyone it granted a zone to loses that entitlement at once, and " +
			"their existing zones become orphaned. Ask the person before calling this.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpRuleDeleteInput) (*mcp.CallToolResult, mcpStatus, error) {
		existing, err := app.Storage.PolicyGetByID(in.ID)
		if err != nil {
			return nil, mcpStatus{}, fmt.Errorf("no rule with id %d", in.ID)
		}
		if err := mcpserve.ConfirmEcho("confirm_zone_pattern", in.ConfirmZonePattern, existing.ZonePattern,
			fmt.Sprintf("rule %d", in.ID)); err != nil {
			return nil, mcpStatus{}, err
		}
		if err := mayManage(existing.ZoneSoa); err != nil {
			return nil, mcpStatus{}, err
		}
		app.Log.Infow("MCP delete_policy_rule", "user", caller.user.Identity(), "rule_id", in.ID)
		if err := app.PolicyDeleteRule(in.ID); err != nil {
			return nil, mcpStatus{}, fmt.Errorf("delete rule %d: %w", in.ID, err)
		}
		return nil, mcpStatus{Status: "ok", Detail: "rule deleted: " + existing.ZonePattern}, nil
	})

	mcpserve.AddTool(s, caller, false, &mcp.Tool{
		Name: "list_delegations",
		Description: "List the delegations that let someone manage policy rules for a zone and everything below " +
			"it. Super-admins only.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, DelegationsResponse, error) {
		if err := requireSuperAdmin(); err != nil {
			return nil, DelegationsResponse{}, err
		}
		delegations, err := app.DelegationGetAll()
		if err != nil {
			return nil, DelegationsResponse{}, fmt.Errorf("list delegations: %w", err)
		}
		return nil, DelegationsResponse{Delegations: delegations}, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "create_delegation",
		Description: "Let a user manage the policy rules for a zone and everything below it. This hands out the " +
			"right to grant zones to others. Super-admins only.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpDelegationInput) (*mcp.CallToolResult, DelegationPolicy, error) {
		if err := requireSuperAdmin(); err != nil {
			return nil, DelegationPolicy{}, err
		}
		app.Log.Infow("MCP create_delegation", "user", caller.user.Identity(), "zone_suffix", in.ZoneSuffix)
		delegation, err := app.DelegationCreate(DelegationPolicyRequest{
			TargetUserFilter: in.TargetUserFilter,
			ZoneSuffix:       in.ZoneSuffix,
			Description:      in.Description,
		})
		if err != nil {
			return nil, DelegationPolicy{}, fmt.Errorf("create delegation: %w", err)
		}
		return nil, *delegation, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name:        "update_delegation",
		Description: "Change a delegation. Every field is given in full, not as a delta. Super-admins only.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpDelegationUpdateInput) (*mcp.CallToolResult, DelegationPolicy, error) {
		if err := requireSuperAdmin(); err != nil {
			return nil, DelegationPolicy{}, err
		}
		app.Log.Infow("MCP update_delegation", "user", caller.user.Identity(), "delegation_id", in.ID)
		delegation, err := app.DelegationUpdate(in.ID, DelegationPolicyRequest{
			TargetUserFilter: in.TargetUserFilter,
			ZoneSuffix:       in.ZoneSuffix,
			Description:      in.Description,
		})
		if err != nil {
			return nil, DelegationPolicy{}, fmt.Errorf("update delegation %d: %w", in.ID, err)
		}
		return nil, *delegation, nil
	})

	mcpserve.AddTool(s, caller, true, &mcp.Tool{
		Name: "delete_delegation",
		Description: "Withdraw a delegation. The user immediately loses the right to manage rules for that zone; " +
			"the rules they created stay. Super-admins only.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in mcpDelegationDeleteInput) (*mcp.CallToolResult, mcpStatus, error) {
		if err := requireSuperAdmin(); err != nil {
			return nil, mcpStatus{}, err
		}
		delegations, err := app.DelegationGetAll()
		if err != nil {
			return nil, mcpStatus{}, fmt.Errorf("list delegations: %w", err)
		}
		var found *DelegationPolicy
		for i := range delegations {
			if delegations[i].ID == in.ID {
				found = &delegations[i]
				break
			}
		}
		if found == nil {
			return nil, mcpStatus{}, fmt.Errorf("no delegation with id %d", in.ID)
		}
		if err := mcpserve.ConfirmEcho("confirm_zone_suffix", in.ConfirmZoneSuffix, found.ZoneSuffix,
			fmt.Sprintf("delegation %d", in.ID)); err != nil {
			return nil, mcpStatus{}, err
		}
		app.Log.Infow("MCP delete_delegation", "user", caller.user.Identity(), "delegation_id", in.ID)
		if err := app.DelegationDelete(in.ID); err != nil {
			return nil, mcpStatus{}, fmt.Errorf("delete delegation %d: %w", in.ID, err)
		}
		return nil, mcpStatus{Status: "ok", Detail: "delegation withdrawn for " + found.ZoneSuffix}, nil
	})

	mcpserve.AddTool(s, caller, false, &mcp.Tool{
		Name: "list_orphaned_zones",
		Description: "List zones that exist but that no current policy rule grants to their owner — usually the " +
			"sign of a mistyped or deleted rule. The fix is to correct the rule, which makes the zone reachable " +
			"again; there is deliberately no tool that deletes one. Super-admins only.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, OrphanedZonesResponse, error) {
		if err := requireSuperAdmin(); err != nil {
			return nil, OrphanedZonesResponse{}, err
		}
		zones, err := app.OrphanedZones()
		if err != nil {
			return nil, OrphanedZonesResponse{}, fmt.Errorf("list orphaned zones: %w", err)
		}
		return nil, OrphanedZonesResponse{Zones: zones}, nil
	})
}
