package app

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/apierr"
	"github.com/pfisterer/cloud-self-service-golib/authn"
	"github.com/pfisterer/cloud-self-service-golib/ginweb"
	"github.com/pfisterer/cloud-self-service-golib/msg"
)

// The answers of authentication and acting on behalf, in German and English (German by default, the caller picks by Accept-Language), each with a stable code a client matches on instead of the text. The same texts as the other services of the platform.
var (
	errUnauthenticated   = apierr.New(http.StatusUnauthorized, "unauthenticated", msg.T("Anmeldung erforderlich.", "Sign-in required."))
	errAPITokenRejected  = apierr.New(http.StatusUnauthorized, "unauthenticated", msg.T("API-Token ungültig, abgelaufen oder gelöscht.", "API token invalid, expired or deleted."))
	errSignInRejected    = apierr.New(http.StatusUnauthorized, "unauthenticated", msg.T("Anmeldung ungültig oder abgelaufen.", "Sign-in invalid or expired."))
	errSignInUnavailable = apierr.New(http.StatusServiceUnavailable, "auth_unavailable", msg.T("Anmeldedienst gerade nicht erreichbar.", "The sign-in service cannot be reached right now."))
	errInternal          = apierr.New(http.StatusInternalServerError, "internal", msg.T("Interner Fehler.", "Internal error."))
	errActAsNeedsSignIn  = apierr.New(http.StatusForbidden, "act_as_forbidden", msg.T("Handeln im Auftrag anderer Personen ist nur nach einer Anmeldung möglich, nicht mit einem API-Token.", "Acting on behalf of other people is only possible after signing in, not with an API token."))
	errActAsInvalid      = apierr.New(http.StatusBadRequest, "act_as_invalid", msg.T("X-Act-As muss eine E-Mail-Adresse sein.", "X-Act-As must be an e-mail address."))
	errActAsForbidden    = apierr.New(http.StatusForbidden, "act_as_forbidden", msg.T("Handeln im Auftrag anderer Personen ist nur für Administratoren möglich.", "Acting on behalf of other people is only possible for administrators."))
)

// errRuleNotFound is the answer for a policy rule id that does not exist.
var errRuleNotFound = statusErr(http.StatusNotFound, msg.T("Die Regel gibt es nicht.", "The rule does not exist."), nil)

// actAsError is the answer to an error of authn.ActAs: 400 for a malformed header, 403 otherwise.
func actAsError(err error) *apierr.Error {
	switch {
	case errors.Is(err, authn.ErrActAsInvalid):
		return errActAsInvalid
	case errors.Is(err, authn.ErrActAsNeedsSignIn):
		return errActAsNeedsSignIn
	default:
		return errActAsForbidden
	}
}

// codeOf is the stable code of an answer of this service with this status: the service's errors carry their status (StatusError), the code follows from it.
func codeOf(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid"
	case http.StatusUnauthorized:
		return "unauthenticated"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusTooManyRequests:
		return "too_many_requests"
	case http.StatusServiceUnavailable:
		return "unavailable"
	default:
		if status >= http.StatusInternalServerError {
			return "internal"
		}
		return "invalid"
	}
}

// apiErr is an answer of this service: the status, its code and the text for people.
func apiErr(status int, text msg.Text) *apierr.Error {
	return apierr.New(status, codeOf(status), text)
}

// abortErr answers the request with status and the text for people, in the request's language.
func abortErr(c *gin.Context, status int, text msg.Text) {
	ginweb.AbortError(c, apiErr(status, text))
}

// serviceErrors is how this service answers the errors of its operations (golib's apierr: the mechanism is shared, this table is the service's). A StatusError carries its status and the message for people, the cause goes to the log; anything else is the service's own failure: 500 with a generic text.
var serviceErrors = apierr.Classifier{
	Rules: []apierr.Rule{
		apierr.As(func(se *StatusError) *apierr.Error { return apiErr(se.Status, se.Msg) }),
	},
	Fallback: func(error) *apierr.Error { return errInternal },
}

// respondError answers err by serviceErrors, logging the cause of a 5xx.
func (app *AppData) respondError(c *gin.Context, err error) {
	e := serviceErrors.Classify(err)
	if e.Status >= http.StatusInternalServerError && app.Log != nil {
		app.Log.Errorw("request failed", "method", c.Request.Method, "path", c.FullPath(), "error", err)
	}
	ginweb.AbortError(c, e)
}

// invalid is a validation message for people (400 where it is answered) in German and English; %w wraps as in fmt.Errorf (msg.Errorf).
func invalid(de, en string, args ...any) error {
	return msg.Errorf(de, en, args...)
}
