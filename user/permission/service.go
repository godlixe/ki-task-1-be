package permission

import (
	"context"
	"encoding/base64"
	"encryption/file"
	"encryption/guard"
	"encryption/helper"
	"encryption/user"
	filepermission "encryption/user/file_permission"
	"errors"
	"fmt"
	"os"

	"crypto/rsa"

	"github.com/google/uuid"
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

type FilePermissionRepository interface {
	GetByPermissionID(
		ctx context.Context,
		permissionID uint64,
	) ([]filepermission.FilePermission, error)

	GetByID(
		ctx context.Context,
		filePermissionID uint64,
	) (filepermission.FilePermission, error)

	CreateFilePermission(
		ctx context.Context,
		filePermission filepermission.FilePermission,
	) error

	GetByUserFilePermission(
		ctx context.Context,
		sourceUserID uint64,
		targetUserID uint64,
		fileID uint64,
	) (filepermission.FilePermission, error)
}

type UserService interface {
	GetUserWithRSA(
		ctx context.Context,
		userID uint64,
	) (*user.User, error)
}

type FileSystem interface {
	Read(path string) ([]byte, error)
	Write(path string, data []byte) error
	NewDir(path string) error
}

type DecryptService interface {
	GetFile(
		ctx context.Context,
		userID uint64,
		id uint64,
	) (*file.File, error)
}

type permissionService struct {
	decryptService           DecryptService
	fileSystem               FileSystem
	filePermissionRepository FilePermissionRepository
	permissionRepository     PermissionRepository
	userRepository           UserRepository
	guard                    guard.Guard
	userService              UserService
}

func NewPermissionService(
	ds DecryptService,
	fs FileSystem,
	fpr FilePermissionRepository,
	pr PermissionRepository,
	ur UserRepository,
	g guard.Guard,
	us UserService,
) *permissionService {
	return &permissionService{
		decryptService:           ds,
		fileSystem:               fs,
		filePermissionRepository: fpr,
		permissionRepository:     pr,
		userRepository:           ur,
		userService:              us,
		guard:                    g,
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

func (ps *permissionService) HasPermission(
	ctx context.Context,
	sourceUserID uint64,
	targetUserID uint64,
) (bool, error) {
	if targetUserID == sourceUserID {
		return true, nil
	}

	_, err := ps.permissionRepository.GetPermissionByUserId(
		ctx, sourceUserID, targetUserID,
	)
	if err != nil && err != pgx.ErrNoRows {
		return false, err
	} else if err == pgx.ErrNoRows {
		return false, nil
	}

	return true, nil
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

	fmt.Println(targetUser.ID, request.UserID, request.TargetUsername)
	if targetUser.ID == request.UserID {
		return nil, errors.New("Request failed. You cannot make request to yourself.")
	}

	permission, err := ps.filePermissionRepository.GetByUserFilePermission(ctx, request.UserID, targetUser.ID, request.FileID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if permission.ID != 0 {
		return nil, errors.New("You already have permission to this user's file.")
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
		FileID:       request.FileID,
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

	firstTime := true

	var permission *Permission
	// check if permission exists
	permission, err = ps.permissionRepository.GetPermissionByUserId(
		ctx,
		sourceUser.ID,
		targetUser.ID,
	)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	var symmetricKey []byte
	var encryptedSymmetricKey []byte

	if permission != nil {
		firstTime = false

		// decrypt symmetric key if permission exists

		key, err := ps.guard.GetKey(ctx, permissionTable, permission.KeyReference)
		if err != nil {
			return nil, err
		}

		// decrypt file to res
		symmetricKey, err = ps.guard.Decrypt(key.PlainKey, permission.Key)
		if err != nil {
			return nil, err
		}

		fmt.Println(string(symmetricKey), symmetricKey, "got")

		// create permission if not exist
	} else if permission == nil {

		// create symmetric key
		stringSymmetricKey, err := ps.guard.GenerateStringKey()
		if err != nil {
			return &RespondPermissionRequestResponse{}, err
		}

		symmetricKey = []byte(stringSymmetricKey)

		// encrypt symmetric key with source user's public key
		publicKey, err := ps.guard.ParsePublicKey(sourceUser.PublicKey)
		if err != nil {
			return &RespondPermissionRequestResponse{}, err
		}

		// encrypt with public key
		encryptedSymmetricKey, err = ps.guard.EncryptRSA(publicKey, symmetricKey)
		if err != nil {
			return &RespondPermissionRequestResponse{}, err
		}

		err = ps.CreatePermission(ctx, sourceUser.ID, targetUser.ID, symmetricKey)
		if err != nil {
			return &RespondPermissionRequestResponse{}, err
		}

		permission, err = ps.permissionRepository.GetPermissionByUserId(
			ctx,
			sourceUser.ID,
			targetUser.ID,
		)
		if err != nil {
			return nil, err
		}

		fmt.Println(string(symmetricKey), symmetricKey, "newly made")
	}

	// get original file
	originalFile, err := ps.decryptService.GetFile(
		ctx,
		targetUser.ID,
		notification.FileID,
	)
	if err != nil {
		return nil, err
	}
	fmt.Println(string(symmetricKey), symmetricKey, "final")

	// encrypt original file with symmetric key
	encryptedFileContent, err := ps.guard.Encrypt(symmetricKey, originalFile.Content)
	if err != nil {
		return nil, err
	}

	dirName := fmt.Sprintf("%v_%v", sourceUser.ID, targetUser.ID)
	err = ps.fileSystem.NewDir("files/" + dirName)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	newFileName := uuid.New().String()

	// save file to new directory
	err = ps.fileSystem.Write("files/"+dirName+"/"+newFileName, encryptedFileContent)
	if err != nil {
		return nil, err
	}

	// create file permission
	err = ps.filePermissionRepository.CreateFilePermission(
		ctx,
		filepermission.FilePermission{
			Filepath:     "files/" + dirName + "/" + newFileName,
			PermissionID: permission.ID,
			FileID:       notification.FileID,
		},
	)
	if err != nil {
		return nil, err
	}

	// acceptance email message
	if firstTime {
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
