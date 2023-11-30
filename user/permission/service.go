package permission

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	GetProfileNotifications(
		ctx context.Context,
		userID uint64,
		status int,
		direction int,
	) ([]ProfileNotification, error)
	GetProfileNotificationById(context.Context, uint64) (*ProfileNotification, error)
	GetProfileNotificationByUserId(context.Context, uint64, uint64) (*ProfileNotification, error)
	CreateProfileNotification(context.Context, ProfileNotification) error
	UpdateProfileNotification(context.Context, ProfileNotification) error
	GetFileNotifications(
		ctx context.Context,
		userID uint64,
		status int,
		direction int,
	) ([]FileNotification, error)
	GetFileNotificationById(context.Context, uint64) (*FileNotification, error)
	GetFileNotificationByUserIdAndFileId(context.Context, uint64, uint64, int) (*FileNotification, error)
	CreateFileNotification(context.Context, FileNotification) error
	UpdateFileNotification(context.Context, FileNotification) error
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

type FileRepository interface {
	Get(context.Context, uint64) (file.File, error)
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
	fileRepository           FileRepository
	guard                    guard.Guard
	userService              UserService
}

func NewPermissionService(
	ds DecryptService,
	fs FileSystem,
	fpr FilePermissionRepository,
	pr PermissionRepository,
	ur UserRepository,
	fr FileRepository,
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
		fileRepository:           fr,
		guard:                    g,
	}
}

func (ps *permissionService) GetProfileNotifications(
	ctx context.Context,
	userID uint64,
	status int,
	direction int,
) ([]ProfileNotification, error) {
	return ps.permissionRepository.GetProfileNotifications(
		ctx,
		userID,
		status,
		direction,
	)
}

func (ps *permissionService) GetFileNotifications(
	ctx context.Context,
	userID uint64,
	status int,
	direction int,
) ([]FileNotification, error) {
	return ps.permissionRepository.GetFileNotifications(
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

	if targetUser.ID == request.UserID {
		return nil, errors.New("Request failed. You cannot make request to yourself.")
	}

	permission, err := ps.permissionRepository.GetPermissionByUserId(ctx, request.UserID, targetUser.ID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if permission != nil {
		return nil, fmt.Errorf("You are already have permission to %s profile", request.TargetUsername)
	}

	notification, err := ps.permissionRepository.GetProfileNotificationByUserId(context.TODO(), request.UserID, targetUser.ID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	if notification != nil {
		// existing notification is pending
		if notification.Status == 0 {
			return nil, errors.New("Existing request is still in pending status. Please wait for approval.")
		}

		// notification is pending
		if notification.Status == 1 {
			notification.Status = 0
			ps.permissionRepository.UpdateProfileNotification(ctx, *notification)
			return &RequestPermissionResponse{}, nil
		}
	}

	notification = &ProfileNotification{
		SourceUserID: request.UserID,
		TargetUserID: targetUser.ID,
		Status:       0,
	}

	err = ps.permissionRepository.CreateProfileNotification(ctx, *notification)
	if err != nil {
		return nil, err
	}

	return &RequestPermissionResponse{}, nil
}

func (ps *permissionService) RequestFilePermission(
	ctx context.Context,
	request RequestPermissionRequest,
) (*RequestPermissionResponse, error) {
	// get file, cek ada gak
	file, err := ps.fileRepository.Get(ctx, request.FileID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if err == pgx.ErrNoRows {
		return nil, errors.New("Requested file not exists")
	}
	if file.ID == request.UserID {
		return nil, errors.New("Request permission failed. You can not request permission to your file.")
	}

	_, err = ps.permissionRepository.GetPermissionByUserId(ctx, request.UserID, file.UserID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("Request permission failed. Please request permission to see profile data first.")
	}

	permission, err := ps.filePermissionRepository.GetByUserFilePermission(ctx, request.UserID, file.UserID, request.FileID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if permission.ID != 0 {
		return nil, errors.New("You already have permission to this user's file.")
	}

	// get notif by user id and file
	notification, err := ps.permissionRepository.GetFileNotificationByUserIdAndFileId(context.TODO(), request.UserID, file.UserID, int(request.FileID))
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	if notification != nil {
		if notification.Status == 0 {
			return nil, errors.New("Existing request is still in pending status. Please wait for approval.")
		}

		if notification.Status == 2 {
			return nil, errors.New("You already have permission to related file")
		}

		if notification.Status == 1 {
			notification.Status = 0
			ps.permissionRepository.UpdateFileNotification(ctx, *notification)
			return &RequestPermissionResponse{}, nil
		}
	}

	notification = &FileNotification{
		SourceUserID: request.UserID,
		TargetUserID: file.UserID,
		FileID:       request.FileID,
		Status:       0,
	}

	err = ps.permissionRepository.CreateFileNotification(ctx, *notification)
	if err != nil {
		return nil, err
	}

	return &RequestPermissionResponse{}, nil
}

func (ps *permissionService) RespondPermissionRequest(
	ctx context.Context,
	request RespondPermissionRequestRequest,
) (*RespondPermissionRequestResponse, error) {
	notification, err := ps.permissionRepository.GetProfileNotificationById(ctx, request.NotificationID)
	if err != nil {
		return nil, err
	}

	if notification.TargetUserID != request.UserID {
		return nil, errors.New("You do not have access to this resource data.")
	}
	if notification.Status == 1 {
		return nil, errors.New("The request permission has already been rejected.")
	}
	if notification.Status == 2 {
		return nil, errors.New("The request permission has already been accepted.")
	}

	// update notification status
	notification.Status = int(request.PermissionStatus)
	err = ps.permissionRepository.UpdateProfileNotification(ctx, *notification)
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
			fmt.Sprintf("Your permission request to see %s profile is rejected", targetUser.Username),
		)
		if err != nil {
			return nil, err
		}

		return &RespondPermissionRequestResponse{
			Message: "Respond success. Notification is sent to requested user.",
		}, nil
	}

	var encryptedSymmetricKey []byte

	symmetricKey, err := ps.guard.GenerateKey()
	if err != nil {
		return &RespondPermissionRequestResponse{}, err
	}

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

	byteTargetUser, err := json.Marshal(targetUser)
	if err != nil {
		return nil, err
	}

	encryptedTargetUser, err := ps.guard.Encrypt(symmetricKey, byteTargetUser)
	if err != nil {
		return nil, err
	}

	err = ps.CreatePermission(ctx, sourceUser.ID, targetUser.ID, symmetricKey)
	if err != nil {
		return &RespondPermissionRequestResponse{}, err
	}

	// create dir
	dirName := fmt.Sprintf("%v_%v", sourceUser.ID, targetUser.ID)
	err = ps.fileSystem.NewDir("files/" + dirName)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// create file
	err = ps.fileSystem.Write("files/"+dirName+"/user.json", encryptedTargetUser)
	if err != nil {
		return nil, err
	}

	// acceptance email message
	err = helper.SendMail(
		sourceUser.Email,
		"Permission Key For "+targetUser.Username,
		fmt.Sprintf(`
	<html>
	Hi %v, your request to view user %v's data has been approved. </br>
	Below is the encrypted key that can be used to view user %v's data. </br>
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

func (ps *permissionService) RespondFilePermissionRequest(
	ctx context.Context,
	request RespondPermissionRequestRequest,
) (*RespondPermissionRequestResponse, error) {
	notification, err := ps.permissionRepository.GetFileNotificationById(ctx, request.NotificationID)
	if err != nil {
		return nil, err
	}

	if notification.TargetUserID != request.UserID {
		return nil, errors.New("You do not have access to this resource data.")
	}
	if notification.Status == 1 {
		return nil, errors.New("The request permission has already been rejected.")
	}
	if notification.Status == 2 {
		return nil, errors.New("The request permission has already been accepted.")
	}

	permission, err := ps.permissionRepository.GetPermissionByUserId(ctx, notification.SourceUserID, notification.TargetUserID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if permission == nil {
		return nil, fmt.Errorf("Permission is not granted. Please request permission to see profile data first.")
	}

	// update notification status
	notification.Status = int(request.PermissionStatus)
	err = ps.permissionRepository.UpdateFileNotification(ctx, *notification)
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

	key, err := ps.guard.GetKey(ctx, permissionTable, permission.KeyReference)
	if err != nil {
		return nil, err
	}

	// decrypt file to res
	symmetricKey, err := ps.guard.Decrypt(key.PlainKey, permission.Key)
	if err != nil {
		return nil, err
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

	fmt.Println("cek 4")
	// encrypt original file with symmetric key
	encryptedFileContent, err := ps.guard.Encrypt(symmetricKey, originalFile.Content)
	if err != nil {
		return nil, err
	}

	fmt.Println("cek 5")
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
