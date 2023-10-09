package file

import (
	"context"
	"encryption/guard"
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
}

type FileRepository interface {
	List(ctx context.Context, fileType string) ([]File, error)
	Create(ctx context.Context, file File) error
	Get(ctx context.Context, id uint64) (File, error)
	Delete(ctx context.Context, id uint64) error
}

type fileService struct {
	fileSystem     FileSystem
	fileRepository FileRepository
	guard          guard.Guard
}

func NewFileService(
	fs FileSystem,
	fr FileRepository,
	g guard.Guard,
) fileService {
	return fileService{
		fileSystem:     fs,
		fileRepository: fr,
		guard:          g,
	}
}

// ListFiles returns a list of file. Listed attributes are
// id, filename, type, and filepath.
func (fs *fileService) listFiles(ctx context.Context, fileType string) ([]File, error) {
	var err error
	res, err := fs.fileRepository.List(ctx, fileType)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (fs *fileService) getFile(ctx context.Context, id uint64) ([]byte, error) {
	var err error
	// get data from db
	data, err := fs.fileRepository.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// get file from filesystem
	fileContent, err := fs.fileSystem.Read(data.Filepath)
	if err != nil {
		return nil, err
	}

	// Get key from db
	key, err := fs.guard.GetKey(ctx, fileTable, data.Metadata)
	if err != nil {
		return nil, err
	}

	// decrypt file to res
	res, err := fs.guard.Decrypt(key.PlainKey, fileContent)
	if err != nil {
		return nil, err
	}

	return res, nil
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
		UserID:   userID,
		Filename: header.Filename,
		Type:     fileType,
		Filepath: "files/" + filepath,
		Metadata: metadata,
	}

	// save file to db
	err = fs.fileRepository.Create(ctx, dFile)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (fs *fileService) deleteFile(ctx context.Context, id uint64) error {
	err := fs.fileRepository.Delete(ctx, id)
	if err != nil {
		return err
	}

	return nil
}
