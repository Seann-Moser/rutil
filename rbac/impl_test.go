package rbac

import (
	"net/http"
	"strings"
	"testing"
)

func TestHasAccess(t *testing.T) {
	tests := []struct {
		requiredAccess int
		currentAccess  int
		want           bool
	}{
		{1, 1, true},
		{2, 2, true},
		{4, 4, true},
		{8, 8, true},
		{1, 2, false},
		{2, 1, false},
		{4, 1, false},
		{8, 1, false},
		{1, 3, true},
		{2, 3, true},
		{4, 3, false},
		{8, 3, false},
		{1, 5, true},
		{4, 5, true},
		{2, 5, false},
		{8, 5, false},
		{1, 15, true},
		{2, 15, true},
		{4, 15, true},
		{8, 15, true},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := HasAccess(tt.requiredAccess, tt.currentAccess); got != tt.want {
				t.Errorf("HasAccess(%d, %d) = %v; want %v", tt.requiredAccess, tt.currentAccess, got, tt.want)
			}
		})
	}

}

func TestHTTPMethodToAccessCode(t *testing.T) {
	tests := []struct {
		methods []string
		want    int
	}{
		{[]string{http.MethodGet}, AccessRead},
		{[]string{http.MethodPost}, AccessWrite},
		{[]string{http.MethodDelete}, AccessDelete},
		{[]string{http.MethodPatch}, AccessUpdate},
		{[]string{http.MethodPut}, AccessUpdate},
		{[]string{http.MethodGet, http.MethodPost}, AccessRead | AccessWrite},
		{[]string{http.MethodGet, http.MethodDelete}, AccessRead | AccessDelete},
		{[]string{http.MethodGet, http.MethodPatch}, AccessRead | AccessUpdate},
		{[]string{http.MethodPost, http.MethodDelete}, AccessWrite | AccessDelete},
		{[]string{http.MethodPost, http.MethodPatch}, AccessWrite | AccessUpdate},
		{[]string{http.MethodDelete, http.MethodPatch}, AccessDelete | AccessUpdate},
		{[]string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPatch}, AccessRead | AccessWrite | AccessDelete | AccessUpdate},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := HTTPMethodToAccessCode(tt.methods...); got != tt.want {
				t.Errorf("HTTPMethodToAccessCode(%v) = %d; want %d", tt.methods, got, tt.want)
			}
		})
	}
}

func TestURLToResourceID(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/resource", ".api.v1.resource"},
		{"/API/V1/RESOURCE", ".api.v1.resource"},
		{"/api/v1/resource-name", ".api.v1.resource_name"},
		{"api/v1/resource-name", "api.v1.resource_name"},
		{"/api/v1/resource-name/", ".api.v1.resource_name."},
		{"/api/v1/resource-name/sub-resource", ".api.v1.resource_name.sub_resource"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := URLToResourceID(tt.path); got != tt.want {
				t.Errorf("URLToResourceID(%q) = %q; want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestCombineAccess(t *testing.T) {
	tests := []struct {
		access []int
		want   int
	}{
		{[]int{1}, 1},
		{[]int{2}, 2},
		{[]int{4}, 4},
		{[]int{8}, 8},
		{[]int{1, 2}, 3},
		{[]int{1, 4}, 5},
		{[]int{1, 8}, 9},
		{[]int{2, 4}, 6},
		{[]int{2, 8}, 10},
		{[]int{4, 8}, 12},
		{[]int{1, 2, 4}, 7},
		{[]int{1, 2, 8}, 11},
		{[]int{1, 4, 8}, 13},
		{[]int{2, 4, 8}, 14},
		{[]int{1, 2, 4, 8}, 15},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := CombineAccess(tt.access...); got != tt.want {
				t.Errorf("CombineAccess(%v) = %d; want %d", tt.access, got, tt.want)
			}
		})
	}
}

func TestJoinResourceID(t *testing.T) {
	tests := []struct {
		ids  []string
		want string
	}{
		{[]string{"api/v1/resource"}, "api.v1.resource"},
		{[]string{"api/v1/resource", "sub-resource"}, "api.v1.resource.sub_resource"},
		{[]string{"api/v1/resource/", "/sub-resource"}, "api.v1.resource.sub_resource"},
		{[]string{"api/v1/resource-name"}, "api.v1.resource_name"},
		{[]string{"api/v1/resource-name", "sub-resource"}, "api.v1.resource_name.sub_resource"},
		{[]string{"api/v1/resource-name/", "/sub-resource"}, "api.v1.resource_name.sub_resource"},
		{[]string{"api/v1/resource", "sub/resource"}, "api.v1.resource.sub.resource"},
		{[]string{"api/v1/resource", "sub-resource", "another-resource"}, "api.v1.resource.sub_resource.another_resource"},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.ids, ","), func(t *testing.T) {
			if got := JoinResourceID(tt.ids...); got != tt.want {
				t.Errorf("JoinResourceID(%v) = %q; want %q", tt.ids, got, tt.want)
			}
		})
	}
}
