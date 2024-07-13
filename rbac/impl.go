package rbac

import (
	"context"
	"fmt"
	"github.com/Seann-Moser/cutil/cachec"
	"github.com/Seann-Moser/cutil/logc"
	"github.com/Seann-Moser/cutil/sqlc"
	"github.com/Seann-Moser/cutil/sqlc/orm"
	"github.com/spf13/pflag"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"regexp"
	"strings"
	"time"
)

const queryType = orm.QueryTypeSQL
const queryDatabase = "rbac"

var _ RBAC = &Impl{}

type Impl struct {
	validResourceName *regexp.Regexp
}

func Flags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("rbac", pflag.ExitOnError)
	return fs
}

func New() *Impl {

	return &Impl{
		validResourceName: regexp.MustCompile(`^([a-z0-9_\-{}]{2,}\.*)+$`),
	}
}

func (r *Impl) InitTables(ctx context.Context, dao *sqlc.DAO) (context.Context, error) {
	ctx, err := sqlc.AddTable[RoleGroup](ctx, dao, queryDatabase, queryType)
	if err != nil {
		return ctx, err
	}
	ctx, err = sqlc.AddTable[Role](ctx, dao, queryDatabase, queryType)
	if err != nil {
		return ctx, err
	}
	ctx, err = sqlc.AddTable[Resource](ctx, dao, queryDatabase, queryType)
	if err != nil {
		return ctx, err
	}
	ctx, err = sqlc.AddTable[RolesInGroup](ctx, dao, queryDatabase, queryType)
	if err != nil {
		return ctx, err
	}
	ctx, err = sqlc.AddTable[RoleResourcePermissions](ctx, dao, queryDatabase, queryType)
	if err != nil {
		return ctx, err
	}
	ctx, err = sqlc.AddTable[UserRole](ctx, dao, queryDatabase, queryType)
	if err != nil {
		return ctx, err
	}
	ctx, err = sqlc.AddTable[UserGroup](ctx, dao, queryDatabase, queryType)
	if err != nil {
		return ctx, err
	}
	ctx, err = sqlc.AddTable[AccountUserGroup](ctx, dao, queryDatabase, queryType)
	if err != nil {
		return ctx, err
	}
	ctx, err = sqlc.AddTable[AccountUserRole](ctx, dao, queryDatabase, queryType)
	if err != nil {
		return ctx, err
	}
	return ctx, nil
}

func (r *Impl) NewGroup(ctx context.Context, groupName string, description string) (*RoleGroup, error) {
	if group, _ := r.GetGroupWithName(ctx, groupName); group != nil {
		return group, nil
	}

	table, err := sqlc.GetTableCtx[RoleGroup](ctx)
	if err != nil {
		return nil, err
	}
	rg := RoleGroup{
		Name:        groupName,
		Description: description,
		Public:      false,
	}
	id, err := table.Insert(ctx, nil, rg)
	rg.ID = id
	return &rg, err
}

func (r *Impl) NewRole(ctx context.Context, roleName string, description string, priority int) (*Role, error) {
	if role, err := r.GetRoleWithName(ctx, roleName); role != nil && err == nil {
		return role, nil
	}
	table, err := sqlc.GetTableCtx[Role](ctx)
	if err != nil {
		return nil, err
	}
	role := Role{
		Name:        roleName,
		Description: description,
		Priority:    priority,
	}
	id, err := table.Insert(ctx, nil, role)
	role.ID = id
	return &role, err
}

func (r *Impl) NewResource(ctx context.Context, resourceID string, description string, resourceType string, data string, public bool) (*Resource, error) {
	table, err := sqlc.GetTableCtx[Resource](ctx)
	if err != nil {
		return nil, err
	}
	resourceID = strings.ToLower(resourceID)

	if !r.validResourceName.MatchString(resourceID) {
		return nil, fmt.Errorf("invalid resource id format(%s)", resourceID)
	}
	logc.Debug(ctx, "new resource. GetResource", zap.String("id", resourceID))
	if resource, _ := r.GetResource(ctx, resourceID); resource != nil {
		return resource, nil
	}
	logc.Debug(ctx, "new resource. Insert", zap.String("id", resourceID))

	resource := Resource{
		ID:           resourceID,
		Description:  description,
		ResourceType: resourceType,
		Data:         data,
		Public:       public,
	}
	_, err = table.Insert(ctx, nil, resource)
	return &resource, err
}

func (r *Impl) AddGroupToUser(ctx context.Context, group *RoleGroup, userID string, userType string) error {
	if group == nil || group.ID == "" {
		return fmt.Errorf("invalid group")
	}
	table, err := sqlc.GetTableCtx[UserGroup](ctx)
	if err != nil {
		return err
	}

	if row, err := orm.QueryTable[UserGroup](table).
		Where(table.GetColumn("user_id"), "=", "", 0, userID).
		Where(table.GetColumn("group_id"), "=", "", 0, group.ID).
		UseCache().
		Run(ctx, nil); err == nil && len(row) > 0 {
		return nil
	}

	ug := UserGroup{
		GroupID:  group.ID,
		UserID:   userID,
		UserType: userType,
	}
	_, err = table.Insert(ctx, nil, ug)
	return err
}

func (r *Impl) RemoveGroupFromUser(ctx context.Context, group *RoleGroup, userID string) error {
	if group == nil || group.ID == "" {
		return fmt.Errorf("invalid group")
	}
	table, err := sqlc.GetTableCtx[UserGroup](ctx)
	if err != nil {
		return err
	}
	ug := UserGroup{
		GroupID: group.ID,
		UserID:  userID,
	}
	return table.Delete(ctx, nil, ug)
}

func (r *Impl) ReplaceGroupInUser(ctx context.Context, group *RoleGroup, userID string) error {
	//TODO implement me
	panic("implement me")
}
func (r *Impl) GetUserGroupWithType(ctx context.Context, userID string, userType string) ([]*UserGroup, error) {
	groups, err := r.GetAllGroupsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	var groupIDs []string
	for _, group := range groups {
		groupIDs = append(groupIDs, group.ID)
	}
	q := sqlc.GetQuery[UserGroup](ctx)
	q.UseCache()
	q.Where(q.Column("group_id"), "in", "", 0, strings.Join(groupIDs, ","))
	q.Where(q.Column("user_type"), "=", "", 0, userType)
	q.OrderBy(q.Column("created_timestamp"))
	return q.Run(ctx, nil)
}

func (r *Impl) AddRoleToUser(ctx context.Context, role *Role, userID string, userType string) error {
	if role == nil || role.ID == "" {
		return fmt.Errorf("invalid role")
	}
	table, err := sqlc.GetTableCtx[UserRole](ctx)
	if err != nil {
		return err
	}

	if row, err := orm.QueryTable[UserRole](table).
		Where(table.GetColumn("user_id"), "=", "", 0, userID).
		Where(table.GetColumn("role_id"), "=", "", 0, role.ID).Run(ctx, nil); err == nil && len(row) > 0 {
		return nil
	}

	ur := UserRole{
		RoleID:   role.ID,
		UserID:   userID,
		UserType: userType,
	}
	_, err = table.Insert(ctx, nil, ur)
	return err
}

func (r *Impl) RemoveRoleFromUser(ctx context.Context, role *Role, userID string) error {
	if role == nil || role.ID == "" {
		return fmt.Errorf("invalid role")
	}
	table, err := sqlc.GetTableCtx[UserRole](ctx)
	if err != nil {
		return err
	}
	ur := UserRole{
		RoleID: role.ID,
		UserID: userID,
	}
	return table.Delete(ctx, nil, ur)
}

func (r *Impl) ReplaceRoleInUser(ctx context.Context, role *Role, userID string) error {
	//TODO implement me
	panic("implement me")
}

func (r *Impl) AddRoleToGroup(ctx context.Context, group *RoleGroup, roles ...*Role) error {
	if group == nil || group.ID == "" {
		return fmt.Errorf("invalid group")
	}
	var roleIDs []string
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
	}

	if len(roleIDs) == 0 {
		return nil
	}
	table, err := sqlc.GetTableCtx[RolesInGroup](ctx)
	if err != nil {
		return err
	}
	foundRoles := map[string]bool{}
	if rows, err := orm.QueryTable[RolesInGroup](table).
		Where(
			table.GetColumn("group_id"),
			"=",
			"",
			0,
			group.ID,
		).
		Where(
			table.GetColumn("role_id"),
			"in",
			"",
			0,
			strings.Join(roleIDs, ","),
		).Run(ctx, nil); err == nil && len(rows) > 0 {
		if len(rows) == len(roles) {
			return nil
		}
		for _, row := range rows {
			foundRoles[row.RoleID] = true
		}
	}
	for _, role := range roles {
		if _, found := foundRoles[role.ID]; found {
			continue
		}
		ur := RolesInGroup{
			GroupID: group.ID,
			RoleID:  role.ID,
		}
		_, err = table.Insert(ctx, nil, ur)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Impl) RemoveRoleFromGroup(ctx context.Context, group *RoleGroup, roles ...*Role) error {
	if group == nil || group.ID == "" {
		return fmt.Errorf("invalid group")
	}
	if len(roles) == 0 {
		return nil
	}
	table, err := sqlc.GetTableCtx[RolesInGroup](ctx)
	if err != nil {
		return err
	}
	for _, role := range roles {
		ur := RolesInGroup{
			GroupID: group.ID,
			RoleID:  role.ID,
		}
		if err = table.Delete(ctx, nil, ur); err != nil {
			return err
		}
	}
	return nil

}

func (r *Impl) ReplaceRoleInGroup(ctx context.Context, group *RoleGroup, roles ...*Role) error {
	//TODO implement me
	panic("implement me")
}

func (r *Impl) GetRole(ctx context.Context, roleID string) (*Role, error) {
	q := sqlc.GetQuery[Role](ctx)
	q.Where(q.Column("id"), "", "", 0, roleID)
	q.UseCache()
	roles, err := q.Run(ctx, nil)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("no role found with id (%s)", roleID)
	}
	return roles[0], nil
}

func (r *Impl) GetRoleWithName(ctx context.Context, name string) (*Role, error) {
	role, err := cachec.GetSetP[Role](ctx, 10*time.Minute, "role", fmt.Sprintf("role_name_%s", name), func(ctx context.Context) (*Role, error) {
		q := sqlc.GetQuery[Role](ctx)
		q.Where(q.Column("name"), "=", "", 0, name)
		q.Build()
		logc.Debug(ctx, "get role with name", zap.String("query", q.Query), zap.Any("args", q.Args()))
		return q.RunSingle(ctx, nil)
	})
	if err != nil {
		return nil, err
	}
	if role != nil {
		return role, nil
	}

	q := sqlc.GetQuery[Role](ctx)
	q.Where(q.Column("name"), "=", "", 0, name)
	q.Build()
	return q.RunSingle(ctx, nil)
}

func (r *Impl) GetGroup(ctx context.Context, groupID string) (*RoleGroup, error) {
	q := sqlc.GetQuery[RoleGroup](ctx)
	q.Where(q.Column("id"), "", "", 0, groupID)
	q.UseCache()
	groups, err := q.Run(ctx, nil)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no group found with id (%s)", groupID)
	}
	return groups[0], nil
}

func (r *Impl) GetGroupWithName(ctx context.Context, name string) (*RoleGroup, error) {
	q := sqlc.GetQuery[RoleGroup](ctx)
	q.Where(q.Column("name"), "", "", 0, name)
	q.UseCache()
	groups, err := q.Run(ctx, nil)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no group found with name (%s)", name)
	}
	return groups[0], nil
}

func (r *Impl) GetResource(ctx context.Context, resourceID string) (*Resource, error) {
	q := sqlc.GetQuery[Resource](ctx)
	q.Where(q.Column("id"), "", "", 0, resourceID)
	q.UseCache()
	resources, err := q.Run(ctx, nil)
	if err != nil {
		return nil, err
	}
	logc.Debug(ctx, "GetResource.found", zap.String("id", resourceID), zap.Any("resources", resources))

	if len(resources) == 0 {
		return nil, fmt.Errorf("no resources found with id (%s)", resourceID)
	}
	return resources[0], nil
}

func (r *Impl) GetResourcesWithPattern(ctx context.Context, resourcePattern string) ([]*Resource, error) {
	q := sqlc.GetQuery[Resource](ctx)
	q.UniqueWhere(q.Column("id"), "REGEXP", "", 0, resourcePattern, true)
	q.UseCache()
	return q.Run(ctx, nil)
}

func (r *Impl) GetAllRoles(ctx context.Context) ([]*Role, error) {
	q := sqlc.GetQuery[Role](ctx)
	return q.OrderBy(q.Column("id")).UseCache().Run(ctx, nil)
}

func (r *Impl) GetAllGroups(ctx context.Context) ([]*RoleGroup, error) {
	q := sqlc.GetQuery[RoleGroup](ctx)
	return q.OrderBy(q.Column("id")).UseCache().Run(ctx, nil)
}

func (r *Impl) GetAllResources(ctx context.Context) ([]*Resource, error) {
	q := sqlc.GetQuery[Resource](ctx)
	return q.OrderBy(q.Column("id")).UseCache().Run(ctx, nil)
}

func (r *Impl) GetAllResourcesForUser(ctx context.Context, userID, accountId string) ([]*Resource, error) {
	roles, err := r.GetAllRolesForUser(ctx, userID, accountId)
	if err != nil {
		return nil, err
	}

	return r.GetResourcesForRole(ctx, roles...)
}

func (r *Impl) GetAllGroupsForUser(ctx context.Context, userID string) ([]*RoleGroup, error) {
	userGroupTable, err := sqlc.GetTableCtx[UserGroup](ctx)
	if err != nil {
		return nil, err
	}
	q := sqlc.GetQuery[RoleGroup](ctx)
	q.Join(userGroupTable.GetColumns(), "")
	//q.UseCache()
	q.Where(userGroupTable.GetColumn("user_id"), "=", "", 0, userID)
	q.OrderBy(q.Column("id"))
	return q.Run(ctx, nil)
}

func (r *Impl) GetRolesInGroup(ctx context.Context, group ...*RoleGroup) ([]*Role, error) {
	userGroupTable, err := sqlc.GetTableCtx[RolesInGroup](ctx)
	if err != nil {
		return nil, err
	}
	var groupIDs []string
	for _, g := range group {
		groupIDs = append(groupIDs, g.ID)
	}
	q := sqlc.GetQuery[Role](ctx)
	q.Join(userGroupTable.GetColumns(), "")
	q.Where(userGroupTable.GetColumn("group_id"), "in", "", 0, strings.Join(groupIDs, ","))
	q.UseCache()
	return q.Run(ctx, nil)
}

func (r *Impl) GetAllRolesForUser(ctx context.Context, userID string, accountID string) ([]*Role, error) {
	userRoleTable, err := sqlc.GetTableCtx[UserRole](ctx)
	if err != nil {
		return nil, err
	}
	q := sqlc.GetQuery[Role](ctx)
	q.Join(userRoleTable.GetColumns(), "")
	q.Where(userRoleTable.GetColumn("user_id"), "=", "", 0, userID)
	roles, err := q.Run(ctx, nil)
	if err != nil {
		return nil, err
	}
	groups, err := r.GetAllGroupsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	groupRoles, err := r.GetRolesInGroup(ctx, groups...)
	if err != nil {
		return nil, err
	}
	roles = append(roles, groupRoles...)
	userAccountRoles, err := r.GetAccountUserRoles(ctx, accountID, userID)
	if err != nil {
		return nil, err
	}
	roles = append(roles, userAccountRoles...)
	if accountID != "" {
		accountRoles, err := r.GetAllRolesForUser(ctx, accountID, "")
		if err != nil {
			return nil, err
		}
		roles = append(roles, accountRoles...)
	}

	return removeDuplicateRoles(roles), nil
}

func (r *Impl) UserHasRole(ctx context.Context, userID string, role *Role) (bool, error) {
	var outputErr error
	q := sqlc.GetQuery[UserRole](ctx)
	q.Where(q.Column("user_id"), "=", "", 0, userID)
	q.Where(q.Column("role_id"), "=", "", 0, role.ID)
	if data, err := q.Run(ctx, nil); err == nil && len(data) > 0 {
		return true, nil
	} else {
		outputErr = multierr.Combine(outputErr)
		logc.Debug(ctx, "user has role query", zap.String("query", q.Query), zap.Any("args", q.Args()))
	}
	userGroupTable, err := sqlc.GetTableCtx[UserGroup](ctx)
	if err != nil {
		return false, err
	}

	qrig := sqlc.GetQuery[RolesInGroup](ctx)
	qrig.Join(userGroupTable.GetColumns(), "")
	qrig.Where(userGroupTable.GetColumn("user_id"), "=", "", 0, userID)
	qrig.Where(qrig.Column("role_id"), "=", "", 0, role.ID)
	if data, err := qrig.Run(ctx, nil); err == nil && len(data) > 0 {
		return true, nil
	} else {
		logc.Debug(ctx, "qrig user has role query", zap.String("query", qrig.Query), zap.Any("args", qrig.Args()))

		outputErr = multierr.Combine(outputErr)
	}
	accounts, _ := r.GetAccountsForUser(ctx, userID)
	for _, account := range accounts {
		if hasRole, _ := r.AccountUserHasRole(ctx, account.AccountID, userID, role); hasRole {
			return true, nil
		}
	}

	return false, outputErr
}

func (r *Impl) UserHasAllRoles(ctx context.Context, userID string, roles ...*Role) (bool, error) {
	var roleIDs []string
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
	}

	var outputErr error
	q := sqlc.GetQuery[UserRole](ctx)
	q.Where(q.Column("user_id"), "=", "", 0, userID)
	q.Where(q.Column("role_id"), "in", "", 0, strings.Join(roleIDs, ","))
	if data, err := q.Run(ctx, nil); err == nil && len(data) > 0 {
		return true, nil
	} else {
		outputErr = multierr.Combine(outputErr)
	}
	userGroupTable, err := sqlc.GetTableCtx[UserGroup](ctx)
	if err != nil {
		return false, err
	}

	qrig := sqlc.GetQuery[RolesInGroup](ctx)
	qrig.Join(userGroupTable.GetColumns(), "")
	qrig.Where(userGroupTable.GetColumn("user_id"), "=", "", 0, userID)
	qrig.Where(qrig.Column("role_id"), "in", "", 0, strings.Join(roleIDs, ","))
	if data, err := qrig.Run(ctx, nil); err == nil && len(data) > 0 {
		return true, nil
	} else {
		outputErr = multierr.Combine(outputErr)
	}
	accounts, _ := r.GetAccountsForUser(ctx, userID)
	for _, account := range accounts {
		if hasRole, _ := r.AccountUserHasAllRoles(ctx, account.AccountID, userID, roles...); hasRole {
			return true, nil
		}
	}
	return false, outputErr
}

func (r *Impl) UserHasAnyRoles(ctx context.Context, userID, accountID string, roles ...*Role) (bool, error) {
	hitDB := false
	userRoles, err := cachec.GetSet[[]*Role](ctx, 30*time.Minute, "role", fmt.Sprintf("%s-%s-role", userID, accountID), func(ctx context.Context) ([]*Role, error) {
		hitDB = true
		return r.GetAllRolesForUser(ctx, userID, accountID)
	})
	if err != nil {
		return false, fmt.Errorf("failed getting user roles: %w", err)
	}
	for _, userRole := range userRoles {
		for _, role := range roles {
			if strings.EqualFold(userRole.ID, role.ID) {
				return true, nil
			}
			if strings.EqualFold(userRole.Name, role.Name) {
				return true, nil
			}
		}
	}
	if !hitDB {
		userRoles, err = r.GetAllRolesForUser(ctx, userID, accountID)
		if err != nil {
			return false, fmt.Errorf("failed getting user roles: %w", err)
		}
		for _, userRole := range userRoles {
			for _, role := range roles {
				if strings.EqualFold(userRole.ID, role.ID) {
					return true, nil
				}
				if strings.EqualFold(userRole.Name, role.Name) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (r *Impl) GetRoleResourcePermissions(ctx context.Context, roles ...*Role) ([]*RoleResourcePermissions, error) {
	q := sqlc.GetQuery[RoleResourcePermissions](ctx)
	var roleIDs []string
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
	}
	q.Where(q.Column("role_id"), "in", "", 0, strings.Join(roleIDs, ","))
	q.UseCache()
	q.Build()
	logc.Info(ctx, "get role resource permissions", zap.String("query", q.Query))
	return q.Run(ctx, nil)
}

func (r *Impl) GetResourcesForRole(ctx context.Context, roles ...*Role) ([]*Resource, error) {
	roleResourcePermissionsTable, err := sqlc.GetTableCtx[RoleResourcePermissions](ctx)
	if err != nil {
		return nil, err
	}
	var roleIDs []string
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
	}

	q := sqlc.GetQuery[Resource](ctx)
	q.Join(roleResourcePermissionsTable.GetColumns(), "")
	q.Where(roleResourcePermissionsTable.GetColumn("role_id"), "in", "", 0, strings.Join(roleIDs, ","))
	q.UseCache()
	q.Build()
	//logc.Info(ctx, "get resources for role", zap.String("query", q.Query), zap.Any("args", q.Args()))
	return q.Run(ctx, nil)
}

func GetResourceIDs(resource ...*Resource) []string {
	var ids []string
	for _, r := range resource {
		ids = append(ids, r.ID)
	}
	return ids
}

func (r *Impl) RoleHasPermission(ctx context.Context, role *Role, resource *Resource, access ...int) (bool, error) {
	//todo fix this matching incorrectly on some resources due to regex
	q := sqlc.GetQuery[RoleResourcePermissions](ctx)
	q.UseCache()
	q.Where(q.Column("role_id"), "=", "AND", 0, role.ID)
	q.Where(q.Column("resource_id"), "in", "AND", 0, strings.Join(GetResourceIDs(resource), ","))
	rows, err := q.Run(ctx, nil)
	if err != nil {
		return false, err
	}
	logc.Debug(ctx, "role has permissions query", zap.String("query", q.Query), zap.Any("args", q.Args()), zap.Any("rows", rows))
	if len(rows) == 0 {
		return false, fmt.Errorf("role does not have permissions to view this resource (%s)", fmt.Sprintf("%s$", resource.ID))
	}
	combinedAccess := CombineAccess(access...)
	for _, row := range rows {
		if HasAccess(row.Access, combinedAccess) {
			logc.Debug(ctx, "role has access to resource",
				zap.String("resource", resource.ID),
				zap.String("role_id", role.ID),
				zap.Int("access", combinedAccess),
				zap.Int("row_access", row.Access))
			return true, nil
		}
	}
	logc.Debug(ctx, "role does not have access to resource",
		zap.String("resource", resource.ID),
		zap.String("role_id", role.ID),
		zap.Int("access", combinedAccess))
	return false, nil

}

func (r *Impl) RoleHasAnyPermission(ctx context.Context, role *Role, resources []*Resource, access ...int) (bool, error) {
	q := sqlc.GetQuery[RoleResourcePermissions](ctx)
	q.Where(q.Column("role_id"), "=", "AND", 0, role.ID)
	q.Where(q.Column("resource_id"), "in", "AND", 0, strings.Join(GetResourceIDs(resources...), ","))
	rows, err := q.Run(ctx, nil)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if HasAccess(row.Access, CombineAccess(access...)) {
			return true, nil
		}
	}
	return false, nil
}

func (r *Impl) RoleHasAllPermissions(ctx context.Context, role *Role, resources []*Resource, access ...int) (bool, error) {
	q := sqlc.GetQuery[RoleResourcePermissions](ctx)
	q.UseCache()
	q.Where(q.Column("role_id"), "=", "AND", 0, role.ID)
	q.Where(q.Column("resource_id"), "in", "AND", 0, strings.Join(GetResourceIDs(resources...), ","))
	rows, err := q.Run(ctx, nil)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if HasAccess(row.Access, CombineAccess(access...)) {
			return true, nil
		}
	}
	return false, nil
}

func (r *Impl) UserHasPermissionForResource(ctx context.Context, userID, accountID string, resource *Resource, access ...int) (bool, error) {
	roles, err := r.GetAllRolesForUser(ctx, userID, accountID)
	if err != nil {
		return false, err
	}
	var roleIDs []string
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
	}

	q := sqlc.GetQuery[RoleResourcePermissions](ctx)
	q.Where(q.Column("role_id"), "in", "AND", 0, strings.Join(roleIDs, ","))
	q.Where(q.Column("resource_id"), "in", "AND", 0, strings.Join(GetResourceIDs(resource), ","))
	q.UseCache()
	q.Build()

	rows, err := q.Run(ctx, nil)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	a := CombineAccess(access...)
	for _, row := range rows {
		if HasAccess(row.Access, a) {
			return true, nil
		}
	}
	return false, fmt.Errorf("user does not have access to resource")
}

func (r *Impl) UserHasAnyPermissionForResource(ctx context.Context, userID, accountID string, resources []*Resource, access ...int) (bool, error) {
	roles, err := r.GetAllRolesForUser(ctx, userID, accountID)
	if err != nil {
		return false, err
	}
	var roleIDs []string
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
	}

	q := sqlc.GetQuery[RoleResourcePermissions](ctx)
	q.Where(q.Column("role_id"), "in", "AND", 0, strings.Join(roleIDs, ","))
	q.Where(q.Column("resource_id"), "in", "AND", 0, strings.Join(GetResourceIDs(resources...), ","))
	q.UseCache()
	rows, err := q.Run(ctx, nil)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	a := CombineAccess(access...)
	for _, row := range rows {
		if HasAccess(row.Access, a) {
			return true, nil
		}
	}
	return false, nil
}

func (r *Impl) AddPermissionResourceToRole(ctx context.Context, role *Role, resource *Resource, access ...int) error {
	q := sqlc.GetQuery[RoleResourcePermissions](ctx)
	q.UseCache()
	q.Where(q.Column("role_id"), "=", "AND", 0, role.ID)
	q.Where(q.Column("resource_id"), "in", "AND", 0, strings.Join(GetResourceIDs(resource), ","))

	q.Where(q.Column("access"), "=", "AND", 0, CombineAccess(access...))
	rows, _ := q.Run(ctx, nil)
	if len(rows) > 0 {
		return nil
	}

	table, err := sqlc.GetTableCtx[RoleResourcePermissions](ctx)
	if err != nil {
		return err
	}
	rrp := RoleResourcePermissions{
		RoleID:          role.ID,
		ResourcePattern: resource.ID,
		ResourceID:      resource.ID,
		Access:          CombineAccess(access...),
	}
	_, err = table.Insert(ctx, nil, rrp)
	return err
}

func (r *Impl) RemovePermissionsFromRole(ctx context.Context, role *Role, resources ...*Resource) error {
	table, err := sqlc.GetTableCtx[RoleResourcePermissions](ctx)
	if err != nil {
		return err
	}
	for _, resource := range resources {
		rrp := RoleResourcePermissions{
			RoleID:          role.ID,
			ResourcePattern: resource.ID,
			ResourceID:      resource.ID,
		}
		err = table.Delete(ctx, nil, rrp)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Impl) ReplacePermissionsInRole(ctx context.Context, role *Role, resource *Resource, access ...int) error {
	//TODO implement me
	panic("implement me")
}

func (r *Impl) NewAccountUserRole(ctx context.Context, accountID string, roleID string, userID string) (*AccountUserRole, error) {
	table, err := sqlc.GetTableCtx[AccountUserRole](ctx)
	if err != nil {
		return nil, err
	}
	aur := &AccountUserRole{
		AccountID: accountID,
		UserID:    userID,
		RoleID:    roleID,
	}
	_, err = table.Insert(ctx, nil, *aur)
	if err != nil {
		return nil, err
	}
	return aur, nil
}

func (r *Impl) DeleteAccountUserRole(ctx context.Context, accountID string, roleID string, userID string) error {
	table, err := sqlc.GetTableCtx[AccountUserRole](ctx)
	if err != nil {
		return err
	}
	aur := &AccountUserRole{
		AccountID: accountID,
		UserID:    userID,
		RoleID:    roleID,
	}

	return table.Delete(ctx, nil, *aur)
}

func (r *Impl) GetAccountUserRoles(ctx context.Context, accountID string, userID string) ([]*Role, error) {
	q := sqlc.GetQuery[AccountUserRole](ctx)
	groups, err := r.GetAccountUserGroup(ctx, accountID, userID)
	if err != nil {
		return nil, err
	}
	q.Where(q.Column("account_id"), "=", "AND", 0, accountID)
	q.Where(q.Column("user_id"), "=", "AND", 0, userID)
	q.UseCache()
	userRoles, err := q.Run(ctx, nil)
	if err != nil {
		return nil, err
	}

	var rg []*RoleGroup
	for _, g := range groups {
		rg = append(rg, &RoleGroup{
			ID: g.GroupID,
		})
	}
	roles, _ := r.GetRolesInGroup(ctx, rg...)

	var roleIDs []string
	for _, ur := range userRoles {
		roleIDs = append(roleIDs, ur.RoleID)
	}

	for _, ur := range roles {
		roleIDs = append(roleIDs, ur.ID)
	}

	roleQ := sqlc.GetQuery[Role](ctx)
	roleQ.UseCache()
	roleQ.Where(
		roleQ.Column("id"),
		"in",
		"",
		0,
		strings.Join(roleIDs, ","),
	).OrderBy(roleQ.Column("priority"))
	return roleQ.Run(ctx, nil)
}

func (r *Impl) GetAllAccountUserRoles(ctx context.Context, accountID string) ([]*Role, error) {
	q := sqlc.GetQuery[AccountUserRole](ctx)
	groups, err := r.GetAllAccountGroups(ctx, accountID)
	if err != nil {
		return nil, err
	}
	q.Where(q.Column("account_id"), "=", "AND", 0, accountID)
	accountRoles, err := q.Run(ctx, nil)
	if err != nil {
		return nil, err
	}
	var rg []*RoleGroup
	for _, g := range groups {
		rg = append(rg, &RoleGroup{
			ID: g.GroupID,
		})
	}
	roles, _ := r.GetRolesInGroup(ctx, rg...)
	var roleIDs []string
	for _, ur := range accountRoles {
		roleIDs = append(roleIDs, ur.RoleID)
	}
	for _, ur := range roles {
		roleIDs = append(roleIDs, ur.ID)
	}

	roleQ := sqlc.GetQuery[Role](ctx)
	roleQ.Where(
		roleQ.Column("id"),
		"in",
		"",
		0,
		strings.Join(roleIDs, ","),
	)
	return roleQ.Run(ctx, nil)
}

func (r *Impl) NewAccountUserGroup(ctx context.Context, accountID string, groupID string, userID string) (*AccountUserGroup, error) {
	table, err := sqlc.GetTableCtx[AccountUserGroup](ctx)
	if err != nil {
		return nil, err
	}

	aur := &AccountUserGroup{
		AccountID: accountID,
		UserID:    userID,
		GroupID:   groupID,
	}
	_, err = table.Insert(ctx, nil, *aur)
	if err != nil {
		return nil, err
	}
	return aur, nil
}

func (r *Impl) DeleteAccountUserGroup(ctx context.Context, accountID string, groupID string, userID string) error {
	table, err := sqlc.GetTableCtx[AccountUserGroup](ctx)
	if err != nil {
		return err
	}
	aur := &AccountUserGroup{
		AccountID: accountID,
		UserID:    userID,
		GroupID:   groupID,
	}

	return table.Delete(ctx, nil, *aur)
}

func (r *Impl) GetAccountUserGroup(ctx context.Context, accountID string, userID string) ([]*AccountUserGroup, error) {
	q := sqlc.GetQuery[AccountUserGroup](ctx)
	q.Where(q.Column("account_id"), "=", "AND", 0, accountID)
	q.Where(q.Column("user_id"), "=", "AND", 0, userID)
	q.UseCache()
	userGroup, err := q.Run(ctx, nil)
	if err != nil {
		return nil, err
	}
	return userGroup, nil
}

func (r *Impl) GetAllAccountGroups(ctx context.Context, accountID string) ([]*AccountUserGroup, error) {
	q := sqlc.GetQuery[AccountUserGroup](ctx)
	q.Where(q.Column("account_id"), "=", "AND", 0, accountID)
	accountGroup, err := q.Run(ctx, nil)
	if err != nil {
		return nil, err
	}
	return accountGroup, nil
}

func (r *Impl) AccountUserHasRole(ctx context.Context, accountID, userID string, role *Role) (bool, error) {
	q := sqlc.GetQuery[AccountUserRole](ctx)
	//todo check group as well
	q.Where(q.Column("account_id"), "=", "AND", 0, accountID)
	q.Where(q.Column("user_id"), "=", "AND", 0, userID)
	q.Where(q.Column("role_id"), "=", "AND", 0, role.ID)
	userRoles, err := q.Run(ctx, nil)
	if err != nil {
		return false, err
	}

	if len(userRoles) == 0 {
		return false, nil
	}
	return true, nil
}

func (r *Impl) AccountUserHasAllRoles(ctx context.Context, accountID, userID string, roles ...*Role) (bool, error) {
	q := sqlc.GetQuery[AccountUserRole](ctx)
	//todo check group as well
	//var roleIDs []string
	//for _, ur := range roles {
	//	roleIDs = append(roleIDs, ur.ID)
	//}
	q.Where(q.Column("account_id"), "=", "AND", 0, accountID)
	q.Where(q.Column("user_id"), "=", "AND", 0, userID)
	for _, role := range roles {
		q.UniqueWhere(q.Column("role_id"), "=", "AND", 0, role.ID, false)

	}
	userRoles, err := q.Run(ctx, nil)
	if err != nil {
		return false, err
	}

	if len(userRoles) == 0 {
		return false, nil
	}
	return true, nil
}

func (r *Impl) AccountUserHasAnyRoles(ctx context.Context, accountID, userID string, roles ...*Role) (bool, error) {
	q := sqlc.GetQuery[AccountUserRole](ctx)
	//todo check group as well
	var roleIDs []string
	for _, ur := range roles {
		roleIDs = append(roleIDs, ur.ID)
	}
	q.Where(q.Column("account_id"), "=", "AND", 0, accountID)
	q.Where(q.Column("user_id"), "=", "AND", 0, userID)
	q.Where(q.Column("role_id"), "in", "AND", 0, strings.Join(roleIDs, ","))
	userRoles, err := q.Run(ctx, nil)
	if err != nil {
		return false, err
	}

	if len(userRoles) == 0 {
		return false, nil
	}
	return true, nil
}

func (r *Impl) AccountUserHasPermissionForResource(ctx context.Context, accountID, userID string, resource *Resource, access ...int) (bool, error) {
	roles, err := r.GetAccountUserRoles(ctx, accountID, userID)
	if err != nil {
		return false, err
	}
	logc.Debug(ctx, "account has roles", zap.Any("roles", roles))
	var roleIDs []string
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
	}
	q := sqlc.GetQuery[RoleResourcePermissions](ctx)
	q.Where(q.Column("role_id"), "in", "AND", 0, strings.Join(roleIDs, ","))
	q.Where(q.Column("resource_id"), "in", "AND", 0, strings.Join(GetResourceIDs(resource), ","))
	q.Build()
	rows, err := q.Run(ctx, nil)
	if err != nil {
		return false, err
	}
	logc.Debug(ctx, "AccountUserHasPermissionForResource", zap.String("query", q.Query), zap.Any("args", q.Args()))
	if len(rows) == 0 {
		return false, nil
	}
	a := CombineAccess(access...)
	for _, row := range rows {
		if HasAccess(row.Access, a) {
			return true, nil
		}
	}
	return false, fmt.Errorf("user does not have access to resource")
}

func (r *Impl) AccountUserHasAnyPermissionForResource(ctx context.Context, accountID, userID string, resources []*Resource, access ...int) (bool, error) {
	roles, err := r.GetAccountUserRoles(ctx, accountID, userID)
	if err != nil {
		return false, err
	}
	roleIDs := make([]string, len(roles))
	for i, role := range roles {
		roleIDs[i] = role.ID
	}
	q := sqlc.GetQuery[RoleResourcePermissions](ctx)
	q.Where(q.Column("role_id"), "in", "AND", 0, strings.Join(roleIDs, ","))
	q.Where(q.Column("resource_id"), "in", "AND", 0, strings.Join(GetResourceIDs(resources...), ","))
	q.UseCache()
	rows, err := q.Run(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("error running query: %w", err)
	}
	if len(rows) == 0 {
		return false, nil
	}
	a := CombineAccess(access...)
	for _, row := range rows {
		if HasAccess(row.Access, a) {
			return true, nil
		}
	}
	return false, nil
}

func (r *Impl) GetAccountsForUser(ctx context.Context, userID string) ([]*AccountUserRole, error) {
	q := sqlc.GetQuery[AccountUserRole](ctx)
	q.Where(q.Column("user_id"), "=", "AND", 0, userID)
	userRoles, err := q.Run(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error running query: %w", err)
	}
	if len(userRoles) == 0 {
		return nil, fmt.Errorf("no accounts found for user ID %s", userID)
	}
	return userRoles, nil
}

func (r *Impl) GetAllAccountUsers(ctx context.Context, accountID string) ([]*AccountUserRole, error) {
	q := sqlc.GetQuery[AccountUserRole](ctx)
	//todo check group as well
	q.Where(q.Column("account_id"), "=", "AND", 0, accountID)
	return q.Run(ctx, nil)
}
