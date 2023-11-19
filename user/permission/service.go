package permission

import (
	"context"
	"encoding/hex"
	"encryption/guard"
	"encryption/helper"
	"encryption/user"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const userKeyTable = "user_keys"
const permissionTable = "permission_keys"

type PermissionRepository interface {
	GetNotifications(
		ctx context.Context,
		userID uint64,
		status int,
		direction int,
	) ([]Notification, error)
	GetNotificationById(context.Context, uint64) (*Notification, error)
	GetLastestNotification(context.Context, uint64, uint64) (*Notification, error)
	CreateNotification(context.Context, Notification) error
	UpdateNotification(context.Context, Notification) error
	GetPermissionByUserId(context.Context, uint64, uint64) (*Permission, error)
	CreatePermission(context.Context, Permission) error
}

type UserRepository interface {
	GetById(context.Context, uint64) (*user.User, error)
	GetByUsername(context.Context, string) (*user.User, error)
}

type Guard interface {
	GenerateKey() ([]byte, error)
}

type permissionService struct {
	permissionRepository PermissionRepository
	userRepository       UserRepository
	guard                guard.Guard
}

func NewPermissionService(
	pr PermissionRepository,
	ur UserRepository,
	g guard.Guard,
) permissionService {
	return permissionService{
		permissionRepository: pr,
		userRepository:       ur,
		guard:                g,
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

func (ps *permissionService) RespondPermissionRequest(
	ctx context.Context,
	request RespondPermissionRequestRequest,
) (*RespondPermissionRequestResponse, error) {
	notification, err := ps.permissionRepository.GetNotificationById(ctx, request.NotificationID)
	if err != nil {
		return nil, err
	}

	if notification.TargetUserID != request.UserID {
		return nil, errors.New("You do not have access to this resource data.")
	}

	if notification.Status != 0 {
		return nil, errors.New("Permission request has been already accept/reject before")
	}

	// update notification status
	notification.Status = int(request.PermissionStatus)
	err = ps.permissionRepository.UpdateNotification(ctx, *notification)
	if err != nil {
		return nil, err
	}

	getDecryptedUser := func(userID uint64) (*user.User, error) {
		user, err := ps.userRepository.GetById(ctx, userID)
		if err != nil {
			return nil, err
		}
		key, err := ps.guard.GetKey(ctx, userKeyTable, user.KeyReference)
		if err != nil {
			return nil, err
		}
		err = user.DecryptUserData(&ps.guard, key)
		return user, err
	}

	sourceUser, err := getDecryptedUser(notification.SourceUserID)
	if err != nil {
		return nil, err
	}
	targetUser, err := getDecryptedUser(notification.TargetUserID)
	if err != nil {
		return nil, err
	}

	var mail helper.Mail

	// send rejection email message
	if request.PermissionStatus == 1 {
		mail = helper.Mail{
			Receiver: []string{sourceUser.Email},
			Subject:  "Permission Request Information",
			Body:     fmt.Sprintf("Your permission request to see %s data is rejected", targetUser.Username),
		}
		err = helper.SendEmail(mail)
		if err != nil {
			return nil, err
		}

		return &RespondPermissionRequestResponse{
			Message: "Respond success. Notification is sent to requested user.",
		}, nil
	}

	// TODO: change to symmetric key generation standard
	symmetricKey, err := ps.guard.GenerateKey()
	if err != nil {
		return nil, err
	}

	// TODO: encrypt encrypted symmetric key encryption using user public key (asymmetric encryption) before sent to email

	permission := Permission{
		SourceUserID: notification.SourceUserID,
		TargetUserID: notification.TargetUserID,
		Key:          symmetricKey,
	}

	err = ps.permissionRepository.CreatePermission(ctx, permission)
	if err != nil {
		return nil, err
	}

	// acceptance email message
	mail = helper.Mail{
		Receiver: []string{sourceUser.Email},
		Subject:  "Permission Request Information",
		Body:     fmt.Sprintf("Your permission request to see %s data is accepted. Here is your key: %s", targetUser.Username, hex.EncodeToString(permission.Key)),
	}

	err = helper.SendEmail(mail)
	if err != nil {
		return nil, err
	}

	return &RespondPermissionRequestResponse{
		Message: "Respond success. Notification is sent to requested user.",
	}, nil
}
