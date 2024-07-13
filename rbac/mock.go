package rbac

import (
	"context"
)

var _ RBAC = &Mock{}

type Mock struct {
}

func (m Mock) GetAllAccountUsers(ctx context.Context, accountID string) ([]*AccountUserRole, error) {
	// Mock implementation returning a predefined list of AccountUserRole objects
	return []*AccountUserRole{
		{
			AccountID:        accountID,
			UserID:           "user1",
			RoleID:           "role1",
			UpdatedTimestamp: "2023-10-01T00:00:00Z",
			CreatedTimestamp: "2023-10-01T00:00:00Z",
		},
		{
			AccountID:        accountID,
			UserID:           "user2",
			RoleID:           "role2",
			UpdatedTimestamp: "2023-10-01T00:00:00Z",
			CreatedTimestamp: "2023-10-01T00:00:00Z",
		},
	}, nil
}

func (m Mock) GetAccountUserGroupRoles(ctx context.Context, accountID string, userID string) ([]*Role, error) {
	// Mock implementation returning a predefined list of Role objects
	return []*Role{
		{
			ID:               "role1",
			Name:             "Admin",
			Description:      "Administrator role",
			Public:           true,
			Priority:         1,
			UpdatedTimestamp: "2023-10-01T00:00:00Z",
			CreatedTimestamp: "2023-10-01T00:00:00Z",
		},
		{
			ID:               "role2",
			Name:             "User",
			Description:      "User role",
			Public:           false,
			Priority:         2,
			UpdatedTimestamp: "2023-10-01T00:00:00Z",
			CreatedTimestamp: "2023-10-01T00:00:00Z",
		},
	}, nil
}

func (m Mock) GetAllAccountGroups(ctx context.Context, accountID string) ([]*AccountUserGroup, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) GetAllAccountGroupRoles(ctx context.Context, accountID string) ([]*Role, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) GetAccountsForUser(ctx context.Context, userID string) ([]*AccountUserRole, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) AccountUserHasRole(ctx context.Context, accountID, userID string, role *Role) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) AccountUserHasAllRoles(ctx context.Context, accountID, userID string, roles ...*Role) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) AccountUserHasAnyRoles(ctx context.Context, accountID, userID string, role ...*Role) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) AccountUserHasPermissionForResource(ctx context.Context, accountID, userID string, resources *Resource, access ...int) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) AccountUserHasAnyPermissionForResource(ctx context.Context, accountID, userID string, resources []*Resource, access ...int) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) NewAccountUserRole(ctx context.Context, accountID string, roleID string, userID string) (*AccountUserRole, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) DeleteAccountUserRole(ctx context.Context, accountID string, roleID string, userID string) error {
	//TODO implement me
	panic("implement me")
}

func (m Mock) GetAccountUserRoles(ctx context.Context, accountID string, userID string) ([]*Role, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) GetAllAccountUserRoles(ctx context.Context, accountID string) ([]*Role, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) NewAccountUserGroup(ctx context.Context, accountID string, roleID string, userID string) (*AccountUserGroup, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) DeleteAccountUserGroup(ctx context.Context, accountID string, roleID string, userID string) error {
	//TODO implement me
	panic("implement me")
}

func (m Mock) GetAccountUserGroup(ctx context.Context, accountID string, userID string) ([]*AccountUserGroup, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) GetAllAccountUserGroup(ctx context.Context, accountID string) ([]*AccountUserGroup, error) {
	//TODO implement me
	panic("implement me")
}

func (m Mock) NewGroup(ctx context.Context, groupName string, description string) (*RoleGroup, error) {
	return nil, nil
}

func (m Mock) NewRole(ctx context.Context, roleName string, description string, priority int) (*Role, error) {
	return nil, nil
}

func (m Mock) NewResource(ctx context.Context, resourceID string, description string, resourceType string, data string, public bool) (*Resource, error) {
	return nil, nil
}

func (m Mock) AddGroupToUser(ctx context.Context, group *RoleGroup, userID string, userType string) error {
	return nil
}

func (m Mock) RemoveGroupFromUser(ctx context.Context, group *RoleGroup, userID string) error {
	return nil
}

func (m Mock) ReplaceGroupInUser(ctx context.Context, group *RoleGroup, userID string) error {
	return nil
}

func (m Mock) AddRoleToUser(ctx context.Context, role *Role, userID string, userType string) error {
	return nil
}

func (m Mock) RemoveRoleFromUser(ctx context.Context, role *Role, userID string) error {
	return nil
}

func (m Mock) ReplaceRoleInUser(ctx context.Context, role *Role, userID string) error {
	return nil
}

func (m Mock) AddPermissionResourceToRole(ctx context.Context, role *Role, resource *Resource, access ...int) error {
	return nil
}

func (m Mock) RemovePermissionsFromRole(ctx context.Context, role *Role, resources ...*Resource) error {
	return nil
}

func (m Mock) ReplacePermissionsInRole(ctx context.Context, role *Role, resource *Resource, access ...int) error {
	return nil
}

func (m Mock) AddRoleToGroup(ctx context.Context, group *RoleGroup, roles ...*Role) error {
	return nil
}

func (m Mock) RemoveRoleFromGroup(ctx context.Context, group *RoleGroup, roles ...*Role) error {
	return nil
}

func (m Mock) ReplaceRoleInGroup(ctx context.Context, group *RoleGroup, roles ...*Role) error {
	return nil
}

func (m Mock) GetRole(ctx context.Context, roleID string) (*Role, error) {
	return nil, nil
}

func (m Mock) GetRoleWithName(ctx context.Context, name string) (*Role, error) {
	return nil, nil
}

func (m Mock) GetGroup(ctx context.Context, groupID string) (*RoleGroup, error) {
	return nil, nil
}

func (m Mock) GetGroupWithName(ctx context.Context, name string) (*RoleGroup, error) {
	return nil, nil
}

func (m Mock) GetResource(ctx context.Context, resourceID string) (*Resource, error) {
	return nil, nil
}

func (m Mock) GetResourcesWithPattern(ctx context.Context, resourcePattern string) ([]*Resource, error) {
	return nil, nil
}

func (m Mock) GetAllRoles(ctx context.Context) ([]*Role, error) {
	return nil, nil
}

func (m Mock) GetAllGroups(ctx context.Context) ([]*RoleGroup, error) {
	return nil, nil
}

func (m Mock) GetAllResources(ctx context.Context) ([]*Resource, error) {
	return nil, nil
}

func (m Mock) GetAllResourcesForUser(ctx context.Context, userID, accountID string) ([]*Resource, error) {
	return nil, nil
}

func (m Mock) GetAllGroupsForUser(ctx context.Context, userID string) ([]*RoleGroup, error) {
	return nil, nil
}

func (m Mock) GetAllRolesForUser(ctx context.Context, userID string, accountID string) ([]*Role, error) {
	return nil, nil
}

func (m Mock) GetRolesInGroup(ctx context.Context, group ...*RoleGroup) ([]*Role, error) {
	return nil, nil
}

func (m Mock) RoleHasPermission(ctx context.Context, role *Role, resource *Resource, access ...int) (bool, error) {
	return false, nil
}

func (m Mock) RoleHasAnyPermission(ctx context.Context, role *Role, resources []*Resource, access ...int) (bool, error) {
	return false, nil
}

func (m Mock) RoleHasAllPermissions(ctx context.Context, role *Role, resources []*Resource, access ...int) (bool, error) {
	return false, nil
}

func (m Mock) GetUserGroupWithType(ctx context.Context, userID string, userType string) ([]*UserGroup, error) {
	return nil, nil
}

func (m Mock) UserHasPermissionForResource(ctx context.Context, userID, accountID string, resources *Resource, access ...int) (bool, error) {
	return false, nil
}

func (m Mock) UserHasAnyPermissionForResource(ctx context.Context, userID, accountID string, resources []*Resource, access ...int) (bool, error) {
	return false, nil
}

func (m Mock) UserHasRole(ctx context.Context, userID string, role *Role) (bool, error) {
	return false, nil
}

func (m Mock) UserHasAllRoles(ctx context.Context, userID string, roles ...*Role) (bool, error) {
	return false, nil
}

func (m Mock) UserHasAnyRoles(ctx context.Context, userID, accountID string, role ...*Role) (bool, error) {
	return false, nil
}

func (m Mock) GetResourcesForRole(ctx context.Context, role ...*Role) ([]*Resource, error) {
	return nil, nil
}

func (m Mock) GetRoleResourcePermissions(ctx context.Context, role ...*Role) ([]*RoleResourcePermissions, error) {
	return nil, nil
}
