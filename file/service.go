package file

import (
	"context"
	"encoding/base64"
	"encryption/cache"
	"encryption/guard"
	"encryption/user"
	"errors"
	"fmt"
	"io"
	"mime/multipart"

	"github.com/google/uuid"
)

const fileTable = "keys"

type Guard interface {
	GetKey(table string, metadata []byte) (guard.Key, error)
	StoreKey(table string, key guard.Key) ([]byte, error)
	GenerateMetadata(key guard.Key) ([]byte, error)
	GenerateKey() ([]byte, error)
	Decrypt(key []byte, data []byte) ([]byte, error)
	Encrypt(key []byte, data []byte) ([]byte, error)
}

type FileSystem interface {
	Read(filepath string) ([]byte, error)
	Write(filepath string, data []byte) error
	NewDir(path string) error
}

type FileRepository interface {
	List(ctx context.Context, userID uint64, fileType string) ([]File, error)
	Create(ctx context.Context, file File) error
	Get(ctx context.Context, id uint64) (File, error)
	Delete(ctx context.Context, id uint64) error
	ListWithCredentials(ctx context.Context, userID uint64) ([]File, error)
}

type UserService interface {
	GetUserByUsername(context.Context, string) (*user.User, error)
}

type fileService struct {
	redisClient    cache.RedisClient
	userService    UserService
	fileSystem     FileSystem
	fileRepository FileRepository
	guard          guard.Guard
}

func NewFileService(
	rc cache.RedisClient,
	us UserService,
	fs FileSystem,
	fr FileRepository,
	g guard.Guard,
) fileService {
	return fileService{
		redisClient:    rc,
		userService:    us,
		fileSystem:     fs,
		fileRepository: fr,
		guard:          g,
	}
}

// ListFiles returns a list of file. Listed attributes are
// id, filename, type, and filepath.
func (fs *fileService) listFiles(
	ctx context.Context,
	userID uint64,
	fileType string,
	targetUsername string,
) ([]File, error) {
	var err error

	token := ctx.Value("user_token").(string)

	targetUser, err := fs.userService.GetUserByUsername(ctx, targetUsername)
	if err != nil {
		return nil, err
	}

	needAuth := true
	if targetUser.ID == userID {
		needAuth = false
	}

	permissionCache, err := fs.redisClient.Get(
		ctx,
		fmt.Sprintf("permission:%v_%v", token, targetUser.ID),
	)
	if err != nil {
		return nil, err
	}

	if needAuth &&
		len(permissionCache) >= 0 &&
		string(permissionCache) == "true" {
		needAuth = false
	}

	if needAuth && targetUser.ID != userID {
		return nil, errors.New("redirect")
	}

	res, err := fs.fileRepository.List(ctx, targetUser.ID, fileType)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (fs *fileService) getFile(ctx context.Context, userID uint64, id uint64) (*File, error) {
	token := ctx.Value("user_token").(string)

	var err error
	// get data from db
	data, err := fs.fileRepository.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// handle if userID doesnt match
	if data.UserID != userID {
		// check permission cache
		permissionCache, err := fs.redisClient.Get(
			ctx,
			fmt.Sprintf("permission:%v_%v", token, data.UserID),
		)
		if err != nil {
			return nil, err
		}

		if len(permissionCache) <= 0 &&
			string(permissionCache) != "true" {
			return nil, errors.New("redirect")
		}
	}

	// get file from filesystem
	fileContent, err := fs.fileSystem.Read(data.Filepath)
	if err != nil {
		return nil, err
	}

	// Get key from db
	key, err := fs.guard.GetKey(ctx, fileTable, data.KeyReference)
	if err != nil {
		return nil, err
	}

	// decrypt file to res
	res, err := fs.guard.Decrypt(key.PlainKey, fileContent)
	if err != nil {
		return nil, err
	}

	return &File{
		Filename: data.Filename,
		Content:  res,
	}, nil
}

func (fs *fileService) storeFile(
	ctx context.Context,
	userID uint64,
	header multipart.FileHeader,
	file multipart.File,
	fileType string,
) ([]byte, error) {
	var err error
	var dFile File

	// create key
	key, err := fs.guard.GenerateKey()
	if err != nil {
		return nil, err
	}

	// store key to db
	metadata, err := fs.guard.StoreKey(ctx, fileTable, guard.Key{
		PlainKey: key,
	})
	if err != nil {
		return nil, err
	}

	// read file
	fileContent, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// encrypt file using key
	res, err := fs.guard.Encrypt(key, fileContent)
	if err != nil {
		return nil, err
	}

	filepath := uuid.New().String()
	fs.fileSystem.Write("files/"+filepath, res)

	dFile = File{
		UserID:       userID,
		Filename:     header.Filename,
		Type:         fileType,
		Filepath:     "files/" + filepath,
		KeyReference: metadata,
	}

	// save file to db
	err = fs.fileRepository.Create(ctx, dFile)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (fs *fileService) deleteFile(ctx context.Context, userID uint64, id uint64) error {
	// get data from db
	data, err := fs.fileRepository.Get(ctx, id)
	if err != nil {
		return err
	}

	// return if userID doesnt match
	if data.UserID != userID {
		return errors.New("unauthorized")
	}

	err = fs.fileRepository.Delete(ctx, id)
	if err != nil {
		return err
	}

	return nil
}

// duplicateUserFiles duplicates and encrypts a user's file with a new key
func (fs *fileService) DuplicateUserFiles(
	ctx context.Context,
	dirName string,
	targetUserID uint64,
	newKey []byte,
) error {
	// get all files from a user
	files, err := fs.fileRepository.ListWithCredentials(ctx, targetUserID)
	if err != nil {
		return err
	}

	var fileKeyReferences [][]byte

	for _, file := range files {
		fileKeyReferences = append(fileKeyReferences, file.KeyReference)
	}

	keys, err := fs.guard.GetMultipleKeys(ctx, fileTable, fileKeyReferences)
	if err != nil {
		return err
	}

	// create a new directory for the files if it doesnt exist
	err = fs.fileSystem.NewDir("files/" + dirName)
	if err != nil {
		return err
	}

	for _, file := range files {
		file.Key = keys[base64.StdEncoding.EncodeToString(file.KeyReference)]

		fileContent, err := fs.fileSystem.Read(file.Filepath)
		if err != nil {
			return err
		}

		decryptedContent, err := fs.guard.Decrypt(file.Key.PlainKey, fileContent)
		if err != nil {
			return err
		}

		// encrypt fileContent with new key
		encryptedContent, err := fs.guard.Encrypt(newKey, decryptedContent)
		if err != nil {
			return err
		}

		err = fs.fileSystem.Write("files/"+dirName+file.Filename, encryptedContent)
		if err != nil {
			return err
		}

	}

	return nil
}
