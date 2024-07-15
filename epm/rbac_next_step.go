package epm

import (
	"context"
	"github.com/Seann-Moser/rutil/rbac"
)

var _ NextStep = (&RbacNextStep{}).RBACNextStep

type RbacNextStep struct {
	rbac rbac.RBAC
}

func NewRbacNextStep(rba rbac.RBAC) *RbacNextStep {
	return &RbacNextStep{rbac: rba}
}

func (r *RbacNextStep) RBACNextStep(ctx context.Context, e *Endpoint) error {
	resource, err := r.rbac.NewResource(ctx, rbac.URLToResourceID(e.Path), "", "endpoint", e.Path, true)
	if err != nil {
		return err
	}
	for _, access := range e.RoleAccess {
		if access.Access == 0 {
			err = r.rbac.AddPermissionResourceToRole(ctx, access.Role, resource, rbac.HTTPMethodToAccessCode(e.Methods...))
			if err != nil {
				return err
			}
		} else {
			err = r.rbac.AddPermissionResourceToRole(ctx, access.Role, resource, access.Access)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
