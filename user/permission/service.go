package permission

import (
	"context"
)

type PermissionRepository interface {
	GetNotifications(
		ctx context.Context,
		userID uint64,
		status int,
		direction int,
	) ([]Notification, error)
}

type permissionService struct {
	permissionRepository PermissionRepository
}

func NewPermissionService(
	pr PermissionRepository,
) permissionService {
	return permissionService{
		permissionRepository: pr,
	}
}

func (ps *permissionService) GetNotifications(
	ctx context.Context,
	userID uint64,
	status int,
	direction int,
) ([]Notification, error) {
	return ps.permissionRepository.GetNotifications(
		ctx,
		userID,
		status,
		direction,
	)
}
