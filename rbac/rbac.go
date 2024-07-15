package rbac

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

const (
	AccessRead   = 1
	AccessWrite  = 2
	AccessUpdate = 4
	AccessDelete = 8
)

// A User can be a firebase uuid, a service account id, or an account id
type AccountUserRole struct {
	AccountID        string `json:"account_id" db:"account_id" qc:"primary;join;join_name::account_id"`
	UserID           string `json:"user_id" db:"user_id" qc:"primary;varchar(512);"`
	RoleID           string `json:"role_id" db:"role_id" qc:"primary;join;foreign_key::id;foreign_table::role"`
	UpdatedTimestamp string `json:"updated_timestamp" db:"updated_timestamp" qc:"skip;default::updated_timestamp"`
	CreatedTimestamp string `json:"created_timestamp" db:"created_timestamp" qc:"skip;default::created_timestamp"`
}

type AccountUserGroup struct {
	AccountID        string `json:"account_id"`
	UserID           string `json:"user_id" db:"user_id" qc:"primary;varchar(512);"`
	GroupID          string `json:"group_id" db:"group_id" qc:"primary;join;foreign_key::id;foreign_table::role_group"`
	UpdatedTimestamp string `json:"updated_timestamp" db:"updated_timestamp" qc:"skip;default::updated_timestamp"`
	CreatedTimestamp string `json:"created_timestamp" db:"created_timestamp" qc:"skip;default::created_timestamp"`
}

type UserRole struct {
	RoleID   string `json:"role_id" db:"role_id" qc:"primary;join;foreign_key::id;foreign_table::role"`
	UserID   string `json:"user_id" db:"user_id" qc:"primary;varchar(512);"`
	UserType string `json:"user_type" db:"user_type" qc:"update"`

	UpdatedTimestamp string `json:"updated_timestamp" db:"updated_timestamp" qc:"skip;default::updated_timestamp"`
	CreatedTimestamp string `json:"created_timestamp" db:"created_timestamp" qc:"skip;default::created_timestamp"`
}

type UserGroup struct {
	GroupID  string `json:"group_id" db:"group_id" qc:"primary;join;foreign_key::id;foreign_table::role_group"`
	UserID   string `json:"user_id" db:"user_id" qc:"primary;varchar(512);"`
	UserType string `json:"user_type" db:"user_type" qc:"update"`

	UpdatedTimestamp string `json:"updated_timestamp" db:"updated_timestamp" qc:"skip;default::updated_timestamp"`
	CreatedTimestamp string `json:"created_timestamp" db:"created_timestamp" qc:"skip;default::created_timestamp"`
}

// RoleGroup Uses Roles
type RoleGroup struct {
	ID          string `json:"id" db:"id" qc:"primary;join;join_name::group_id;auto_generate_id"`
	Name        string `json:"name" db:"name" qc:"update;data_type::varchar(512);"`
	Description string `json:"description" db:"description" qc:"data_type::varchar(512);update"`
	Public      bool   `json:"public" db:"public" qc:"default::false;update"`

	UpdatedTimestamp string `json:"updated_timestamp" db:"updated_timestamp" qc:"skip;default::updated_timestamp"`
	CreatedTimestamp string `json:"created_timestamp" db:"created_timestamp" qc:"skip;default::created_timestamp"`
}

type RolesInGroup struct {
	GroupID string `json:"group_id" db:"group_id" qc:"primary;join;foreign_key::id;foreign_table::role_group"`
	RoleID  string `json:"role_id" db:"role_id" qc:"primary;join;foreign_key::id;foreign_table::role"`

	UpdatedTimestamp string `json:"updated_timestamp" db:"updated_timestamp" qc:"skip;default::updated_timestamp"`
	CreatedTimestamp string `json:"created_timestamp" db:"created_timestamp" qc:"skip;default::created_timestamp"`
}

// Role has permissions
type Role struct {
	ID          string `json:"id" db:"id" qc:"primary;join;join_name::role_id;auto_generate_id"`
	Name        string `json:"name" db:"name" qc:"update;data_type::varchar(512);"`
	Description string `json:"description" db:"description" qc:"data_type::varchar(512);update"`
	Public      bool   `json:"public" db:"public" qc:"default::false;update"`
	Priority    int    `json:"priority" db:"priority" qc:"default::0;update"`

	UpdatedTimestamp string `json:"updated_timestamp" db:"updated_timestamp" qc:"skip;default::updated_timestamp"`
	CreatedTimestamp string `json:"created_timestamp" db:"created_timestamp" qc:"skip;default::created_timestamp"`
}

type Resource struct {
	ID           string `json:"id" db:"id" qc:"primary;join;join_name::resource_id;data_type::varchar(1024);"` // ID ("resource.*")
	Description  string `json:"description" db:"description" qc:"data_type::varchar(512);update"`
	ResourceType string `json:"resource_type" db:"resource_type" qc:"update"` // ResourceType "url"
	Data         string `json:"data" db:"data" qc:"update;text"`
	Public       bool   `json:"public" db:"public" qc:"default::false;update"`

	UpdatedTimestamp string `json:"updated_timestamp" db:"updated_timestamp" qc:"skip;default::updated_timestamp"`
	CreatedTimestamp string `json:"created_timestamp" db:"created_timestamp" qc:"skip;default::created_timestamp"`
}

type RoleResourcePermissions struct {
	RoleID           string `json:"role_id" db:"role_id" qc:"primary;join;foreign_key::id;foreign_table::role"`
	ResourcePattern  string `json:"resource_pattern" db:"resource_pattern" qc:"update;data_type::varchar(512);"` // ResourcePattern allows define resource mask using "*" ("resource.*")
	ResourceID       string `json:"resource_id" db:"resource_id" qc:"primary;update;join;foreign_key::id;foreign_table::resource"`
	Access           int    `json:"access" db:"access" qc:"update;primary"`
	UpdatedTimestamp string `json:"updated_timestamp" db:"updated_timestamp" qc:"skip;default::updated_timestamp"`
	CreatedTimestamp string `json:"created_timestamp" db:"created_timestamp" qc:"skip;default::created_timestamp"`
}

type RBAC interface {
	GetAccountsForUser(ctx context.Context, userID string) ([]*AccountUserRole, error)

	NewAccountUserRole(ctx context.Context, accountID string, roleID string, userID string) (*AccountUserRole, error)
	DeleteAccountUserRole(ctx context.Context, accountID string, roleID string, userID string) error
	GetAccountUserRoles(ctx context.Context, accountID string, userID string) ([]*Role, error)
	GetAllAccountUserRoles(ctx context.Context, accountID string) ([]*Role, error)
	GetAllAccountUsers(ctx context.Context, accountID string) ([]*AccountUserRole, error)

	NewAccountUserGroup(ctx context.Context, accountID string, groupID string, userID string) (*AccountUserGroup, error)
	DeleteAccountUserGroup(ctx context.Context, accountID string, groupID string, userID string) error
	GetAccountUserGroup(ctx context.Context, accountID string, userID string) ([]*AccountUserGroup, error)
	//GetAccountUserGroupRoles(ctx context.Context, accountID string, userID string) ([]*Role, error)

	GetAllAccountGroups(ctx context.Context, accountID string) ([]*AccountUserGroup, error)
	//GetAllAccountGroupRoles(ctx context.Context, accountID string) ([]*Role, error)

	AccountUserHasRole(ctx context.Context, accountID, userID string, role *Role) (bool, error)
	AccountUserHasAllRoles(ctx context.Context, accountID, userID string, roles ...*Role) (bool, error)
	AccountUserHasAnyRoles(ctx context.Context, accountID, userID string, role ...*Role) (bool, error)
	AccountUserHasPermissionForResource(ctx context.Context, accountID, userID string, resources *Resource, access ...int) (bool, error)
	AccountUserHasAnyPermissionForResource(ctx context.Context, accountID, userID string, resources []*Resource, access ...int) (bool, error)

	NewGroup(ctx context.Context, groupName string, description string) (*RoleGroup, error)
	NewRole(ctx context.Context, roleName string, description string, priority int) (*Role, error)
	NewResource(ctx context.Context, resourceID string, description string, resourceType string, data string, public bool) (*Resource, error)

	AddGroupToUser(ctx context.Context, group *RoleGroup, userID string, userType string) error
	RemoveGroupFromUser(ctx context.Context, group *RoleGroup, userID string) error
	ReplaceGroupInUser(ctx context.Context, group *RoleGroup, userID string) error

	AddRoleToUser(ctx context.Context, role *Role, userID string, userType string) error
	RemoveRoleFromUser(ctx context.Context, role *Role, userID string) error
	ReplaceRoleInUser(ctx context.Context, role *Role, userID string) error

	AddPermissionResourceToRole(ctx context.Context, role *Role, resource *Resource, access ...int) error
	RemovePermissionsFromRole(ctx context.Context, role *Role, resources ...*Resource) error
	ReplacePermissionsInRole(ctx context.Context, role *Role, resource *Resource, access ...int) error

	AddRoleToGroup(ctx context.Context, group *RoleGroup, roles ...*Role) error
	RemoveRoleFromGroup(ctx context.Context, group *RoleGroup, roles ...*Role) error
	ReplaceRoleInGroup(ctx context.Context, group *RoleGroup, roles ...*Role) error

	GetRole(ctx context.Context, roleID string) (*Role, error)
	GetRoleWithName(ctx context.Context, name string) (*Role, error)

	GetGroup(ctx context.Context, groupID string) (*RoleGroup, error)
	GetGroupWithName(ctx context.Context, name string) (*RoleGroup, error)
	GetResource(ctx context.Context, resourceID string) (*Resource, error)
	GetResourcesWithPattern(ctx context.Context, resourcePattern string) ([]*Resource, error)

	GetAllRoles(ctx context.Context) ([]*Role, error)
	GetAllGroups(ctx context.Context) ([]*RoleGroup, error)
	GetAllResources(ctx context.Context) ([]*Resource, error)
	GetAllResourcesForUser(ctx context.Context, userID, accountId string) ([]*Resource, error)
	GetAllGroupsForUser(ctx context.Context, userID string) ([]*RoleGroup, error)
	GetAllRolesForUser(ctx context.Context, userID string, accountID string) ([]*Role, error)
	GetRolesInGroup(ctx context.Context, group ...*RoleGroup) ([]*Role, error)

	RoleHasPermission(ctx context.Context, role *Role, resource *Resource, access ...int) (bool, error)
	RoleHasAnyPermission(ctx context.Context, role *Role, resources []*Resource, access ...int) (bool, error)
	RoleHasAllPermissions(ctx context.Context, role *Role, resources []*Resource, access ...int) (bool, error)

	GetUserGroupWithType(ctx context.Context, userID string, userType string) ([]*UserGroup, error)

	UserHasPermissionForResource(ctx context.Context, userID, accountID string, resources *Resource, access ...int) (bool, error)
	UserHasAnyPermissionForResource(ctx context.Context, userID, accountID string, resources []*Resource, access ...int) (bool, error)

	UserHasRole(ctx context.Context, userID string, role *Role) (bool, error)
	UserHasAllRoles(ctx context.Context, userID string, roles ...*Role) (bool, error)
	UserHasAnyRoles(ctx context.Context, userID, accountID string, role ...*Role) (bool, error)

	GetResourcesForRole(ctx context.Context, role ...*Role) ([]*Resource, error)

	GetRoleResourcePermissions(ctx context.Context, role ...*Role) ([]*RoleResourcePermissions, error)
}

func JoinResourceID(ids ...string) string {
	replacer := strings.NewReplacer(
		"/", ".",
		"-", "_",
	)
	var output []string
	for _, id := range ids {
		id = replacer.Replace(id)
		id = strings.TrimPrefix(id, ".")
		id = strings.TrimSuffix(id, ".")
		output = append(output, id)
	}

	return strings.Join(output, ".")
}

func URLToResourceID(path string) string {
	replacer := strings.NewReplacer(
		"/", ".",
		"-", "_",
	)
	return replacer.Replace(strings.ToLower(path))
}

var methodToAccessCode = map[string]int{
	http.MethodGet:    AccessRead,
	http.MethodPost:   AccessWrite,
	http.MethodDelete: AccessDelete,
	http.MethodPatch:  AccessUpdate,
	http.MethodPut:    AccessUpdate,
}

func HTTPMethodToAccessCode(methods ...string) int {
	output := 0
	for _, method := range methods {
		if accessCode, exists := methodToAccessCode[method]; exists {
			output |= accessCode
		}
	}
	return output
}

func HasAccess(requiredAccess int, currentAccess int) bool {
	//1111 | 0001 = 0001
	return requiredAccess&currentAccess > 0
}

func CombineAccess(access ...int) int {
	//1111 | 0001 = 0001
	output := 0
	for _, a := range access {
		output |= a
	}
	return output
}

func removeDuplicateRoles(intSlice []*Role) []*Role {
	keys := make(map[string]bool)
	var list []*Role

	for _, entry := range intSlice {
		if !keys[entry.ID] {
			keys[entry.ID] = true
			list = append(list, entry)
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Priority > list[j].Priority
	})
	return list
}
