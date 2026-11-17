package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Token prefixes of the role provider: a person is user:<email>, a group group:<id>, a relation in a group group:<id>#<relation>.
const (
	tokenUserPrefix  = "user:"
	tokenGroupPrefix = "group:"
)

// Defaults of the role-provider cache: an answer is reused for roleProviderFresh, kept as fallback for an unreachable role provider for roleProviderKeep, and after a failed request the role provider is not asked again for roleProviderBackoff (so an outage does not make every request wait for a timeout).
const (
	roleProviderFresh   = 60 * time.Second
	roleProviderKeep    = 24 * time.Hour
	roleProviderBackoff = 15 * time.Second
	roleProviderTimeout = 3 * time.Second
)

// RoleProvider resolves a person's tokens (GET /v1/users/{email}/tokens of role-provider-service) and caches them per person. A nil *RoleProvider is a deployment without a role provider: everybody holds only their own user:<email> token, which is exactly the e-mail matching of before.
type RoleProvider struct {
	baseURL string
	token   string
	client  *http.Client
	log     *zap.SugaredLogger

	fresh, keep, backoff time.Duration
	now                  func() time.Time

	mu        sync.Mutex
	entries   map[string]tokenEntry
	downUntil time.Time
}

type tokenEntry struct {
	tokens  map[string]struct{}
	fetched time.Time
}

// NewRoleProvider returns nil (no role provider) when baseURL is empty.
func NewRoleProvider(baseURL, token string, log *zap.SugaredLogger) *RoleProvider {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	return &RoleProvider{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: roleProviderTimeout},
		log:     log,
		fresh:   roleProviderFresh,
		keep:    roleProviderKeep,
		backoff: roleProviderBackoff,
		now:     time.Now,
		entries: map[string]tokenEntry{},
	}
}

// principal is a person as the policy sees them: their address and the tokens they hold. known is false when the role provider could not be asked and no answer of the last roleProviderKeep is at hand — then group entries of a filter can be neither confirmed nor ruled out.
type principal struct {
	email  string
	tokens map[string]struct{}
	known  bool
}

// Resolve returns the person's tokens: from the cache while fresh, else from the role provider, else (unreachable) the last known answer of the past day, else only their user token with known=false. Never fails; problems are logged.
func (r *RoleProvider) Resolve(email string) principal {
	email = strings.ToLower(strings.TrimSpace(email))
	own := map[string]struct{}{tokenUserPrefix + email: {}}
	if r == nil || email == "" {
		return principal{email: email, tokens: own, known: true}
	}

	r.mu.Lock()
	entry, cached := r.entries[email]
	now := r.now()
	if cached && now.Sub(entry.fetched) < r.fresh {
		r.mu.Unlock()
		return principal{email: email, tokens: entry.tokens, known: true}
	}
	down := now.Before(r.downUntil)
	r.mu.Unlock()

	if !down {
		tokens, err := r.fetch(email)
		if err == nil {
			tokens[tokenUserPrefix+email] = struct{}{}
			r.mu.Lock()
			r.entries[email] = tokenEntry{tokens: tokens, fetched: r.now()}
			r.pruneLocked()
			r.mu.Unlock()
			return principal{email: email, tokens: tokens, known: true}
		}
		r.log.Warnw("role provider unreachable, using the last known tokens if any", "email", email, "error", err)
		r.mu.Lock()
		r.downUntil = r.now().Add(r.backoff)
		r.mu.Unlock()
	}

	if cached && now.Sub(entry.fetched) < r.keep {
		return principal{email: email, tokens: entry.tokens, known: true}
	}
	r.log.Warnw("role provider unreachable and no tokens known for this person; group entries cannot be checked", "email", email)
	return principal{email: email, tokens: own, known: false}
}

// pruneLocked drops answers older than the fallback period, so the cache stays bounded by the people seen within a day.
func (r *RoleProvider) pruneLocked() {
	if len(r.entries) < 1024 {
		return
	}
	now := r.now()
	for k, e := range r.entries {
		if now.Sub(e.fetched) >= r.keep {
			delete(r.entries, k)
		}
	}
}

func (r *RoleProvider) fetch(email string) (map[string]struct{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), roleProviderTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/v1/users/"+url.PathEscape(email)+"/tokens", nil)
	if err != nil {
		return nil, err
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("role provider answered %d", resp.StatusCode)
	}
	var list []string
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("role provider answer: %w", err)
	}
	tokens := make(map[string]struct{}, len(list)+1)
	for _, t := range list {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			tokens[t] = struct{}{}
		}
	}
	return tokens, nil
}

// principalOf resolves a person through the configured role provider (none: e-mail matching only).
func (app *AppData) principalOf(email string) principal {
	return app.Roles.Resolve(email)
}

// filterMatch is the verdict of a user filter for a person: match when an entry matches for certain; unknown when none does but a group entry could not be checked because the person's tokens are unknown (role provider unreachable, nothing cached).
type filterMatch struct {
	match, unknown bool
}

// allowed is the verdict for granting something new (strict: unknown is no) or, with optimistic, for keeping what exists (unknown counts as yes).
func (m filterMatch) allowed(optimistic bool) bool {
	return m.match || (optimistic && m.unknown)
}

// matchFilter evaluates a comma-separated user filter for a person. An entry matches when it is an e-mail address or *-pattern matching the address (case-insensitive), user:<email> naming the address, or a group:<id> / group:<id>#<relation> token the person holds.
func matchFilter(p principal, filter string) filterMatch {
	var m filterMatch
	for _, raw := range strings.Split(filter, ",") {
		entry := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case entry == "":
		case strings.HasPrefix(entry, tokenUserPrefix):
			if strings.TrimSpace(strings.TrimPrefix(entry, tokenUserPrefix)) == p.email {
				return filterMatch{match: true}
			}
		case strings.HasPrefix(entry, tokenGroupPrefix):
			if _, ok := p.tokens[entry]; ok {
				return filterMatch{match: true}
			}
			if !p.known {
				m.unknown = true
			}
		default:
			if emailMatchesPattern(p.email, entry) {
				return filterMatch{match: true}
			}
		}
	}
	return m
}
