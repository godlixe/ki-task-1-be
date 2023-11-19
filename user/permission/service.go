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
	GetLastestNotification(context.Context, uint64, uint64) (*Notification, error)
	CreateNotification(context.Context, Notification) error
	GetPermissionByUserId(context.Context, uint64, uint64) (*Permission, error)
type UserRepository interface {
	GetByUsername(context.Context, string) (*user.User, error)
}

}

type permissionService struct {
	permissionRepository PermissionRepository
	userRepository       UserRepository
}

func NewPermissionService(
	pr PermissionRepository,
	ur UserRepository,
) permissionService {
	return permissionService{
		permissionRepository: pr,
		userRepository:       ur,
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

func (ps *permissionService) RequestPermission(
	ctx context.Context,
	request RequestPermissionRequest,
) (*RequestPermissionResponse, error) {
	targetUser, err := ps.userRepository.GetByUsername(context.TODO(), request.TargetUsername)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New("User with related username does not exist")
		}
		return nil, err
	}

	if targetUser.ID == request.UserID {
		return nil, errors.New("Request failed. You cannot make request to yourself.")
	}

	permission, err := ps.permissionRepository.GetPermissionByUserId(ctx, request.UserID, targetUser.ID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if permission != nil {
		return nil, errors.New("You already have permission to this user.")
	}

	existingNotification, err := ps.permissionRepository.GetLastestNotification(context.TODO(), request.UserID, targetUser.ID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	if existingNotification != nil && existingNotification.Status == 0 {
		return nil, errors.New("Existing request is still in pending status. Please wait for approval.")
	}

	// else scenario: request permission never been created or has been rejected before
	notification := Notification{
		SourceUserID: request.UserID,
		TargetUserID: targetUser.ID,
		Status:       0,
	}

	ps.permissionRepository.CreateNotification(ctx, notification)

	return &RequestPermissionResponse{}, nil
}

