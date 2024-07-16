package epm

import (
	"context"
	"fmt"
	"github.com/Seann-Moser/rutil"
	"github.com/Seann-Moser/rutil/rbac"
	"net/http"
	"regexp"
	"strings"
)

type NextStep func(ctx context.Context, e *Endpoint) error

var EndpointVarIDs = map[string]string{}

var endpointVarIDsRe = regexp.MustCompile(`{([^}]+)}`)

type Endpoint struct {
	Name        string             `json:"name"`
	Path        string             `rf:"required" json:"path"`
	RoleAccess  map[string]*Access `rf:"required" json:"role_access"`
	QueryParams []string           `json:"query_params"`
	Methods     []string           `rf:"required" json:"methods"`
	f           http.HandlerFunc   `rf:"required"`
}

type Access struct {
	Role   *rbac.Role
	Access int
}

func (e *Endpoint) AddQueryParams(name ...string) *Endpoint {
	if e.QueryParams == nil {
		e.QueryParams = name
	} else {
		e.QueryParams = append(e.QueryParams, name...)
	}
	return e
}

func (e *Endpoint) AddRoles(access int, roles ...*rbac.Role) *Endpoint {
	if e.RoleAccess == nil {
		e.RoleAccess = map[string]*Access{}
	}
	for _, role := range roles {
		if _, ok := e.RoleAccess[role.Name]; ok {
			e.RoleAccess[role.ID].Access = rbac.CombineAccess(e.RoleAccess[role.ID].Access, access)
		} else {
			e.RoleAccess[role.ID] = &Access{
				Role:   role,
				Access: access,
			}
		}
	}

	return e
}

func (e *Endpoint) SetPath(path string) *Endpoint {
	// Step 1: Set e.Path
	e.Path = path

	// Step 2: Extract all values between {}
	matches := endpointVarIDsRe.FindAllStringSubmatch(path, -1)

	// Step 3: Add them to the global EndpointVarIDs
	for _, match := range matches {
		if len(match) > 1 {
			EndpointVarIDs[match[1]] = match[1]
		}
	}
	return e
}

func (e *Endpoint) SetMethods(methods ...string) *Endpoint {
	e.Methods = methods
	return e
}

// todo SetResponse
func (e *Endpoint) SetResponse(status int, t interface{}, method ...string) *Endpoint {
	return e
}

// todo SetRequest
func (e *Endpoint) SetRequest(status int, t interface{}, method ...string) *Endpoint {
	return e
}

// todo Equal
func (e *Endpoint) Equal(r *http.Request) bool {
	return false
}

func (e *Endpoint) SetFunc(f *http.HandlerFunc) bool {
	e.f = *f
	return false
}

func (e *Endpoint) Valid() error {
	return rutil.CheckRequiredFields[Endpoint](*e)
}

func (e *Endpoint) AddToRoute(ctx context.Context, mux *http.ServeMux, NextSteps ...NextStep) error {
	for _, m := range e.Methods {
		if e.f != nil {
			mux.HandleFunc(fmt.Sprintf("%s %s", strings.ToUpper(m), e.Path), e.f)
		} else {
			return fmt.Errorf("endpoint does not have router function '%s' ", e.Path)
		}

	}

	for _, next := range NextSteps {
		err := next(ctx, e)
		if err != nil {
			return fmt.Errorf("endpoint next '%s' failed: %w", e.Path, err)
		}
	}
	return nil
}

func GetRawPath(r *http.Request, possibleVars ...string) (map[string]string, string) {
	if len(possibleVars) == 0 {
		possibleVars = rutil.MapKeys[string, string](EndpointVarIDs)
	}
	rawPath := r.URL.Path
	output := make(map[string]string)
	for _, possibleVar := range possibleVars {
		v := r.PathValue(possibleVar)
		if v != "" {
			output[possibleVar] = v
			rawPath = strings.ReplaceAll(rawPath, v, fmt.Sprintf("{%s}", possibleVar))
		}
	}
	return output, rawPath
}
