package permission

import (
	"context"
	"encoding/base64"
	"encryption/guard"
	"encryption/helper"
	"encryption/user"
	"errors"
	"fmt"

	"crypto/rsa"

	"github.com/jackc/pgx/v5"
)

const userKeyTable = "user_keys"
const permissionTable = "permission_keys"

type Guard interface {
	GetKey(ctx context.Context, table string, metadata []byte) (guard.Key, error)
	StoreKey(ctx context.Context, table string, key guard.Key) ([]byte, error)
	GenerateKey() ([]byte, error)
	GenerateStringKey() (string, error)
	Decrypt(key []byte, data []byte) ([]byte, error)
	Encrypt(key []byte, data []byte) ([]byte, error)
	ParsePublicKey(key string) (*rsa.PublicKey, error)
	EncryptRSA(publicKey *rsa.PublicKey, data []byte) ([]byte, error)
	DecryptRSA(publicKey *rsa.PrivateKey, data []byte) ([]byte, error)
}

type PermissionRepository interface {
	GetNotifications(
		ctx context.Context,
		userID uint64,
		status int,
		direction int,
	) ([]Notification, error)
	GetNotificationById(context.Context, uint64) (*Notification, error)
	GetNotificationByUserId(context.Context, uint64, uint64) (*Notification, error)
	CreateNotification(context.Context, Notification) error
	UpdateNotification(context.Context, Notification) error
	GetPermissionByUserId(context.Context, uint64, uint64) (*Permission, error)
	CreatePermission(context.Context, Permission) error
}

type UserRepository interface {
	GetById(context.Context, uint64) (*user.User, error)
	GetByUsername(context.Context, string) (*user.User, error)
}

type UserService interface {
	GetUserWithRSA(
		ctx context.Context,
		userID uint64,
	) (*user.User, error)
}

type permissionService struct {
	permissionRepository PermissionRepository
	userRepository       UserRepository
	guard                guard.Guard
	userService          UserService
}

func NewPermissionService(
	pr PermissionRepository,
	ur UserRepository,
	g guard.Guard,
	us UserService,
) *permissionService {
	return &permissionService{
		permissionRepository: pr,
		userRepository:       ur,
		userService:          us,
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

	existingNotification, err := ps.permissionRepository.GetNotificationByUserId(context.TODO(), request.UserID, targetUser.ID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	if existingNotification != nil {
		if existingNotification.Status == 0 {
			return nil, errors.New("Existing request is still in pending status. Please wait for approval.")
		}

		if existingNotification.Status == 1 {
			existingNotification.Status = 0
			ps.permissionRepository.UpdateNotification(ctx, *existingNotification)
			return &RequestPermissionResponse{}, nil
		}
	}

	notification := Notification{
		SourceUserID: request.UserID,
		TargetUserID: targetUser.ID,
		Status:       0,
	}

	err = ps.permissionRepository.CreateNotification(ctx, notification)
	if err != nil {
		return nil, err
	}

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

	// update notification status
	notification.Status = int(request.PermissionStatus)
	err = ps.permissionRepository.UpdateNotification(ctx, *notification)
	if err != nil {
		return nil, err
	}

	// get source user
	sourceUser, err := ps.userService.GetUserWithRSA(
		ctx,
		notification.SourceUserID,
	)
	if err != nil {
		return &RespondPermissionRequestResponse{}, err
	}

	// get target user
	targetUser, err := ps.userService.GetUserWithRSA(
		ctx,
		notification.TargetUserID,
	)
	if err != nil {
		return &RespondPermissionRequestResponse{}, err
	}
	fmt.Println(sourceUser, targetUser)
	// send rejection email message
	if request.PermissionStatus == 1 {

		err = helper.SendMail(
			sourceUser.Email,
			"Permission Request Information",
			fmt.Sprintf("Your permission request to see %s data is rejected", targetUser.Username),
		)
		if err != nil {
			return nil, err
		}

		return &RespondPermissionRequestResponse{
			Message: "Respond success. Notification is sent to requested user.",
		}, nil
	}

	// create symmetric key
	symmetricKey, err := ps.guard.GenerateStringKey()
	if err != nil {
		return &RespondPermissionRequestResponse{}, err
	}

	// encrypt symmetric key with source user's public key
	publicKey, err := ps.guard.ParsePublicKey(sourceUser.PublicKey)
	if err != nil {
		return &RespondPermissionRequestResponse{}, err
	}

	// encrypt with public key
	encryptedSymmetricKey, err := ps.guard.EncryptRSA(publicKey, []byte(symmetricKey))
	if err != nil {
		return &RespondPermissionRequestResponse{}, err
	}

	err = ps.CreatePermission(ctx, sourceUser.ID, targetUser.ID, []byte(symmetricKey))
	if err != nil {
		return &RespondPermissionRequestResponse{}, err
	}

	// acceptance email message

	err = helper.SendMail(
		sourceUser.Email,
		"Permission Key For "+targetUser.Username,
		fmt.Sprintf(`
		<html>
		Hi %v, your request to view user %v's profile has been approved. </br>
		Below is the encrypted key that can be used to view user %v's profile. </br>
		Note that the key can only be used by your profile to view.
		</br>
		</br>
		</br>

		%v
		</html>
		`, sourceUser.Username,
			targetUser.Username,
			targetUser.Username,
			base64.StdEncoding.EncodeToString(encryptedSymmetricKey),
		),
	)
	if err != nil {
		return nil, err
	}

	return &RespondPermissionRequestResponse{
		Message: "Respond success. Notification is sent to requested user.",
	}, nil
}

func (ps *permissionService) CreatePermission(
	ctx context.Context,
	sourceUserID uint64,
	targetUserID uint64,
	symmetricKey []byte,
) error {
	// create key
	key, err := ps.guard.GenerateKey()
	if err != nil {
		return err
	}

	// store key to db
	metadata, err := ps.guard.StoreKey(ctx, permissionTable, guard.Key{
		PlainKey: key,
	})
	if err != nil {
		return err
	}

	// encrypt symmetric key
	encryptedKey, err := ps.guard.Encrypt(key, symmetricKey)
	if err != nil {
		return err
	}

	return ps.permissionRepository.CreatePermission(ctx, Permission{
		SourceUserID: sourceUserID,
		TargetUserID: targetUserID,
		Key:          encryptedKey,
		KeyReference: metadata,
	})
}
