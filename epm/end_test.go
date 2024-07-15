package epm

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetRawPath(t *testing.T) {
	tests := []struct {
		url          string
		vars         map[string]string
		possibleVars []string
		expectedMap  map[string]string
		expectedPath string
	}{
		{
			url: "/api/v1/resource/123",
			vars: map[string]string{
				"id": "123",
			},
			possibleVars: []string{"id"},
			expectedMap: map[string]string{
				"id": "123",
			},
			expectedPath: "/api/v1/resource/{id}",
		},
		{
			url: "/api/v1/resource/123/action",
			vars: map[string]string{
				"id":     "123",
				"action": "action",
			},
			possibleVars: []string{"id", "action"},
			expectedMap: map[string]string{
				"id":     "123",
				"action": "action",
			},
			expectedPath: "/api/v1/resource/{id}/{action}",
		},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, tt.url, nil)
		for _, v := range tt.possibleVars {
			req.SetPathValue(v, tt.vars[v])
		}

		output, rawPath := GetRawPath(req, tt.possibleVars...)

		assert.Equal(t, tt.expectedMap, output)
		assert.Equal(t, tt.expectedPath, rawPath)
	}
}

func TestEndpointValid(t *testing.T) {
	tests := []struct {
		input         Endpoint
		expectedError error
	}{
		{
			input: Endpoint{
				Name: "ResourceEndpoint",
				Path: "/api/v1/resource",
				RoleAccess: map[string]*Access{"id": &Access{
					Role:   nil,
					Access: 0,
				}},
				QueryParams: nil,
				Methods:     []string{http.MethodGet},
			},
			expectedError: nil,
		},
		{
			input: Endpoint{
				Path: "",
				Name: "ResourceEndpoint",
			},
			expectedError: errors.New("missing required field(s): Path,RoleAccess,Methods"),
		},
		{
			input: Endpoint{
				Path: "/api/v1/resource",
				Name: "",
			},
			expectedError: errors.New("missing required field(s): RoleAccess,Methods"),
		},
		{
			input: Endpoint{
				Path: "",
				Name: "",
			},
			expectedError: errors.New("missing required field(s): Path,RoleAccess,Methods"),
		},
	}

	for _, tt := range tests {
		err := tt.input.Valid()
		if tt.expectedError == nil {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, tt.expectedError.Error())
		}
	}
}
