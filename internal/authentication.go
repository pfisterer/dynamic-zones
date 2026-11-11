package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/authn"
	"github.com/pfisterer/cloud-self-service-golib/credential"
	"github.com/pfisterer/cloud-self-service-golib/ginweb"
	"github.com/pfisterer/cloud-self-service-golib/oidcauth"
	"github.com/pfisterer/cloud-self-service-golib/retry"
	"github.com/pfisterer/cloud-self-service-golib/token"
	"go.uber.org/zap"
)

const UserDataKey = "__api_userData"

// actorKey holds the signed-in admin while a request acts on somebody's behalf; UserDataKey then holds that somebody.
const actorKey = "__api_actor"

// viaAPITokenKey marks a request authenticated with an API token rather than a sign-in.
const viaAPITokenKey = "__api_viaAPIToken"

// ActorOf is the signed-in admin acting on behalf of the request's user, or "" when the user acts themself.
func ActorOf(c *gin.Context) string { return c.GetString(actorKey) }

// ActAsMiddleware lets a super admin act on behalf of another person, e.g. for a ticket: with X-Act-As the request's user (UserDataKey) becomes that person — their zones, their policies, their %u — and is no super admin unless they are one. Every service of the platform reads the same header and checks it against its own admins. Refused rather than ignored for anybody else, and for API tokens: acting on behalf is for people signed in. Must run after CombinedAuthMiddleware.
func ActAsMiddleware(superAdmins map[string]struct{}, log *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader(authn.ActAsHeader)
		v, ok := c.Get(UserDataKey)
		if header == "" || !ok {
			c.Next()
			return
		}
		if c.GetBool(viaAPITokenKey) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": authn.ErrActAsNeedsSignIn.Error()})
			return
		}
		actor := v.(*UserClaims).Identity()
		_, may := superAdmins[strings.ToLower(actor)]
		target, err := authn.ActAs(header, actor, may)
		if err != nil {
			status := http.StatusForbidden
			if errors.Is(err, authn.ErrActAsInvalid) {
				status = http.StatusBadRequest
			}
			c.AbortWithStatusJSON(status, gin.H{"error": err.Error()})
			return
		}
		if target != actor {
			if authn.IsWrite(c.Request.Method) {
				log.Infow("acting on behalf", "actor", actor, "as", target, "method", c.Request.Method, "path", c.Request.URL.Path)
			}
			c.Set(UserDataKey, &UserClaims{Email: target})
			c.Set(actorKey, actor)
		}
		c.Next()
	}
}

// The read-only-token rule (recording the flag, reading it, and refusing writes
// for it) lives in cloud-self-service-golib/ginweb, shared with the other
// services. This file only records the flag via ginweb.SetReadOnly once it has
// resolved the token below.

// UserClaims holds the relevant user information extracted from the ID token.
//
// An alias rather than a type of its own: the identity of a caller has to mean
// the same thing in every service — a token issued here and a group resolved
// elsewhere only line up if both agree on the string. The definition lives in
// the shared module; this name stays because the call sites read well with it.
type UserClaims = authn.Claims

// OIDCVerifierConfig holds the minimal configuration for OIDC token
// verification. JWKSURL is what keeps an identity provider that is down from
// taking this service with it — see the oidcauth package for the whole story.
type OIDCVerifierConfig = oidcauth.Config

// OIDCAuthVerifier manages the OIDC token verification process.
type OIDCAuthVerifier struct {
	Verifier *oidcauth.Verifier
	Logger   *zap.SugaredLogger
}

// NewOIDCAuthVerifier initializes a new OIDCAuthVerifier. With a key set
// configured this makes no network call, so the provider being away is a state
// this service can report rather than a reason to die. Without one the issuer's discovery is tried again for up to a minute (oidcauth.NewWithRetry): right after a pod starts the NetworkPolicies may not let it through yet.
func NewOIDCAuthVerifier(cfg OIDCVerifierConfig, log *zap.SugaredLogger) (*OIDCAuthVerifier, error) {
	verifier, err := oidcauth.NewWithRetry(context.Background(), cfg, log, retry.Policy{Total: time.Minute})
	if err != nil {
		return nil, err
	}
	return &OIDCAuthVerifier{Verifier: verifier, Logger: log}, nil
}

// KeysUnavailable reports whether the identity provider is currently
// unreachable, for the status the UI shows.
func (m *OIDCAuthVerifier) KeysUnavailable() bool {
	return m != nil && m.Verifier.KeysUnavailable()
}

// ingestRoutes are the only routes the zone-events ingest identity may call (method + route pattern, as gin.Context.FullPath reports it).
var ingestRoutes = map[string]bool{
	http.MethodPost + " /v1/zone-events/":             true,
	http.MethodPost + " /v1/zone-events/alertmanager": true,
}

// devUser is who a request without a bearer is; "" outside development mode.
//
// ingestSubject is the zone-events producer's identity (ZONE_EVENTS_INGEST_SUBJECT). Its token is provisioned from configuration and never expires, so it is confined here to the two ingest routes: anywhere else it would be an ordinary, writable account that nobody signs in as and nobody watches.
//
// There is no unauthenticated path for OPTIONS: CORS preflights on /v1 are answered by the CORS middleware before this runs, and every other OPTIONS request (e.g. on /mcp, which has no CORS) has to authenticate like any other.
func CombinedAuthMiddleware(oidcVerifier *OIDCAuthVerifier, store *Storage, log *zap.SugaredLogger, devUser, ingestSubject string) gin.HandlerFunc {
	ingestSubject = strings.TrimSpace(ingestSubject)
	var verifier credential.Verifier
	if oidcVerifier != nil && oidcVerifier.Verifier != nil {
		verifier = oidcVerifier.Verifier
	}
	var tokens credential.Tokens
	if store != nil && store.Tokens != nil {
		tokens = store.Tokens
	}
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		authHeader := c.GetHeader("Authorization")

		// Dev-only: a request without a bearer is the dev user (DEV_AUTH_USER),
		// nothing is verified; other people are reached with X-Act-As, as in
		// production. Gated on devMode and NEVER active in production (devMode
		// is false there).
		if devUser != "" && authHeader == "" {
			c.Set(UserDataKey, &UserClaims{Email: devUser})
			ginweb.SetReadOnly(c, false)
			c.Next()
			return
		}

		// Which case the credential is (none, an API token, an ID token, rejected, the provider away) is decided by golib's credential.Resolve, the same in every service of the platform; the answers here are this service's. A token with this service's prefix is looked up and never sent to the provider.
		p, err := credential.Resolve(ctx, authHeader, tokens, verifier)
		switch {
		case err == nil:
		case errors.Is(err, credential.ErrMissing):
			if _, ok := authn.CutBearerPrefix(authHeader); ok {
				log.Debug("Bearer token is empty. Denying access.")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Bearer token missing"})
				return
			}
			// The header value itself is never logged: a client sending a valid
			// token under an unexpected scheme would write its credential into
			// the log. The scheme alone is what makes this diagnosable.
			log.Warnf("Missing or invalid Authorization header (scheme %q)", authn.Scheme(authHeader))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization Bearer header"})
			return
		case errors.Is(err, token.ErrNotFound):
			// An expired token is not found, so the answer here needs no expiry check of its own.
			log.Warn("Invalid API token, returning unauthorized")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		case errors.Is(err, credential.ErrKeysUnavailable):
			// A token nobody can judge right now is not a rejected token. 401
			// would tell the browser to drop its session and sign in again,
			// which is impossible while the provider is away — the user would
			// loop through a login that cannot finish and read it as our fault.
			log.Warnw("cannot verify tokens: the identity provider is unreachable", "error", err)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "sign-in is temporarily unavailable: the identity provider cannot be reached",
			})
			return
		case errors.Is(err, credential.ErrRejected):
			cause := credential.Cause(err)
			log.Warnf("Failed to verify ID token from Authorization header: %v. Denying access.", cause)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Invalid or expired token: %v", cause)})
			return
		case errors.Is(err, credential.ErrNoVerifier):
			log.Error("OIDC verifier is not configured")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		default:
			log.Warnf("storage error: %v", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		if p.ViaAPIToken() {
			if ingestSubject != "" && p.Token.Subject == ingestSubject && !ingestRoutes[c.Request.Method+" "+c.FullPath()] {
				log.Warnf("The zone-events ingest token was used for %s %s, refusing", c.Request.Method, c.Request.URL.Path)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "this token may only ingest zone events"})
				return
			}
			c.Set(viaAPITokenKey, true)
		}
		// Recorded here, enforced by the route group: what counts as a write
		// is a property of the OPERATION, and only the REST routes can read
		// that off the HTTP method (see RejectWritesForReadOnlyTokens). An
		// interactive login is never read-only.
		ginweb.SetReadOnly(c, p.ReadOnly)

		// For an API token one field, because there is one identity. The token
		// was issued under this subject (see tokenSubject) and Identity() reads
		// Email first, so this is the string every later lookup resolves to —
		// zone ownership, policy matching and the %u expansion alike.
		//
		// It used to fill all three claims, and that was not tidiness: for a
		// while it filled only preferred_username, while policy rules matched
		// on Email. Such a token authenticated cleanly and then matched NO
		// rule — its holder saw the zones they already owned and was entitled
		// to nothing, and every create was refused.
		//
		// The probe that used to sit here is gone, together with the question it
		// asked. It watched for a verified ID token whose `email` and
		// `preferred_username` disagreed, because this service keyed zone and
		// token ownership on one and policy rules on the other — and no database
		// here could prove they always matched, since each stores only one.
		//
		// It never answered: over 36 hours of production it saw 8 authenticated
		// requests and not one login, which is what a semester break looks like.
		// Keycloak answered it instead, and completely rather than by sample —
		// 260 accounts in `dhbw-main`, zero with an `email` differing from the
		// username, zero without an address at all (2026-08-26). Everything now
		// reads Claims.Identity() and there is nothing left to compare.
		c.Set(UserDataKey, p.Claims)
		c.Next()
	}
}
