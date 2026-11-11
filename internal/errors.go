package app

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/apierr"
	"github.com/pfisterer/cloud-self-service-golib/authn"
	"github.com/pfisterer/cloud-self-service-golib/ginweb"
)

// The answers of authentication and acting on behalf, in German like every message to people on the platform, each with a stable code a client matches on instead of the text. The same texts as the other services of the platform.
var (
	errUnauthenticated   = apierr.New(http.StatusUnauthorized, "unauthenticated", "Anmeldung erforderlich.")
	errAPITokenRejected  = apierr.New(http.StatusUnauthorized, "unauthenticated", "API-Token ungültig, abgelaufen oder gelöscht.")
	errSignInRejected    = apierr.New(http.StatusUnauthorized, "unauthenticated", "Anmeldung ungültig oder abgelaufen.")
	errSignInUnavailable = apierr.New(http.StatusServiceUnavailable, "auth_unavailable", "Anmeldedienst gerade nicht erreichbar.")
	errInternal          = apierr.New(http.StatusInternalServerError, "internal", "Interner Fehler.")
	errActAsNeedsSignIn  = apierr.New(http.StatusForbidden, "act_as_forbidden", "Handeln im Auftrag anderer Personen ist nur nach einer Anmeldung möglich, nicht mit einem API-Token.")
	errActAsInvalid      = apierr.New(http.StatusBadRequest, "act_as_invalid", "X-Act-As muss eine E-Mail-Adresse sein.")
	errActAsForbidden    = apierr.New(http.StatusForbidden, "act_as_forbidden", "Handeln im Auftrag anderer Personen ist nur für Administratoren möglich.")
)

// errRuleNotFound is the answer for a policy rule id that does not exist.
var errRuleNotFound = statusErr(http.StatusNotFound, "Die Regel gibt es nicht.", nil)

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
func apiErr(status int, msg string) *apierr.Error {
	return apierr.New(status, codeOf(status), msg)
}

// abortErr answers the request with status and the text for people.
func abortErr(c *gin.Context, status int, msg string) {
	ginweb.AbortError(c, apiErr(status, msg))
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

// invalid is a validation message for people (400 where it is answered); %w wraps as in fmt.Errorf. A function of its own because the texts are German sentences, capitalised and with a full stop, which staticcheck refuses in a literal fmt.Errorf.
func invalid(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
