package decrypt

import (
	"context"
	"encryption/cache"
	"encryption/file"
	"encryption/guard"
	"errors"
	"fmt"
)

const fileTable = "keys"

type FileRepository interface {
	List(ctx context.Context, userID uint64, fileType string) ([]file.File, error)
	Create(ctx context.Context, file file.File) error
	Get(ctx context.Context, id uint64) (file.File, error)
	Delete(ctx context.Context, id uint64) error
}

type Guard interface {
	GetKey(ctx context.Context, table string, metadata []byte) (guard.Key, error)
	StoreKey(ctx context.Context, table string, key guard.Key) ([]byte, error)
	GenerateMetadata(key guard.Key) ([]byte, error)
	GenerateKey() ([]byte, error)
	Decrypt(key []byte, data []byte) ([]byte, error)
	Encrypt(key []byte, data []byte) ([]byte, error)
}

type FileSystem interface {
	Read(filepath string) ([]byte, error)
	Write(filepath string, data []byte) error
}

type decryptService struct {
	fileRepository FileRepository
	fileSystem     FileSystem
	redisClient    cache.RedisClient
	guard          Guard
}

func NewDecryptService(
	fr FileRepository,
	fs FileSystem,
	rc cache.RedisClient,
	g Guard,
) *decryptService {
	return &decryptService{
		fileRepository: fr,
		fileSystem:     fs,
		redisClient:    rc,
		guard:          g,
	}
}

func (ds *decryptService) GetFile(
	ctx context.Context,
	userID uint64,
	id uint64,
) (*file.File, error) {
	token := ctx.Value("user_token").(string)

	var err error
	// get data from db
	data, err := ds.fileRepository.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// handle if userID doesnt match
	if data.UserID != userID {
		// check permission cache
		permissionCache, err := ds.redisClient.Get(
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
	fileContent, err := ds.fileSystem.Read(data.Filepath)
	if err != nil {
		return nil, err
	}

	// Get key from db
	key, err := ds.guard.GetKey(ctx, fileTable, data.KeyReference)
	if err != nil {
		return nil, err
	}

	// decrypt file to res
	res, err := ds.guard.Decrypt(key.PlainKey, fileContent)
	if err != nil {
		return nil, err
	}

	return &file.File{
		Filename: data.Filename,
		Content:  res,
	}, nil
}
