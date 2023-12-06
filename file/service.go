package file

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"encryption/cache"
	"encryption/guard"
	"encryption/user"
	filepermission "encryption/user/file_permission"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const fileTable = "keys"

type Guard interface {
	GetKey(table string, metadata []byte) (guard.Key, error)
	StoreKey(table string, key guard.Key) ([]byte, error)
	GenerateMetadata(key guard.Key) ([]byte, error)
	GenerateKey() ([]byte, error)
	Decrypt(key []byte, data []byte) ([]byte, error)
	Encrypt(key []byte, data []byte) ([]byte, error)
	SignRSA(privateKey *rsa.PrivateKey, data []byte) ([]byte, error)
	VerifyRSA(publicKey *rsa.PublicKey, signature []byte, data []byte) ([]byte, error)
}

type FileSystem interface {
	Read(filepath string) ([]byte, error)
	Write(filepath string, data []byte) error
}

type FileRepository interface {
	List(ctx context.Context, userID uint64, fileType string) ([]File, error)
	Create(ctx context.Context, file File) error
	Get(ctx context.Context, id uint64) (File, error)
	UpdateSignedStatus(ctx context.Context, file File) error
	Delete(ctx context.Context, id uint64) error
}

type UserService interface {
	GetUserByUsername(context.Context, string) (*user.User, error)
	GetUserWithRSA(context.Context, uint64) (*user.User, error)
}

type PermissionService interface {
	HasPermission(
		ctx context.Context,
		sourceUserID uint64,
		targetUserID uint64,
	) (bool, error)
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

	ListByUserFilePermission(
		ctx context.Context,
		sourceUserID uint64,
		targetUserID uint64,
	) ([]filepermission.FilePermission, error)
}

type fileService struct {
	filePermissionRepository FilePermissionRepository
	permissionService        PermissionService
	redisClient              cache.RedisClient
	userService              UserService
	fileSystem               FileSystem
	fileRepository           FileRepository
	guard                    guard.Guard
}

func NewFileService(
	fpr FilePermissionRepository,
	ps PermissionService,
	rc cache.RedisClient,
	us UserService,
	fs FileSystem,
	fr FileRepository,
	g guard.Guard,
) fileService {
	return fileService{
		filePermissionRepository: fpr,
		permissionService:        ps,
		redisClient:              rc,
		userService:              us,
		fileSystem:               fs,
		fileRepository:           fr,
		guard:                    g,
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

	// token := ctx.Value("user_token").(string)

	targetUser, err := fs.userService.GetUserByUsername(ctx, targetUsername)
	if err != nil {
		return nil, err
	}

	// permissionCache, err := fs.redisClient.Get(
	// 	ctx,
	// 	fmt.Sprintf("permission:%v_%v", token, targetUser.ID),
	// )
	// if err != nil {
	// 	return nil, err
	// }

	// return from json if permission exists

	res, err := fs.fileRepository.List(ctx, targetUser.ID, fileType)
	if err != nil {
		return nil, err
	}

	// get user's permissions if user is not owner
	if userID != targetUser.ID {
		filePermissions, err := fs.filePermissionRepository.ListByUserFilePermission(
			ctx,
			userID,
			targetUser.ID,
		)
		if err != nil {
			return nil, err
		}

		var filePermissionMap = make(map[uint64]filepermission.FilePermission)

		for _, data := range filePermissions {
			filePermissionMap[data.File.ID] = data
		}

		for idx, data := range res {
			res[idx].FilePermissions = filePermissionMap[data.ID]
		}
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

	// handle if userID is another user
	if data.UserID != userID {

		// check cache
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
		// check if user has file permission
		filePermission, err := fs.filePermissionRepository.GetByUserFilePermission(
			ctx,
			userID,
			data.UserID,
			data.ID,
		)
		if err != nil {
			return nil, err
		}

		if filePermission.ID == 0 {
			return nil, errors.New("permission does not exist")
		}

		// get symmetric key from permission
		// Get key from db
		symmetricKeyKey, err := fs.guard.GetKey(ctx, "permission_keys", filePermission.Permission.KeyReference)
		if err != nil {
			return nil, err
		}

		// decrypt file to res
		symmetricKey, err := fs.guard.Decrypt(symmetricKeyKey.PlainKey, filePermission.Permission.Key)
		if err != nil {
			return nil, err
		}

		fileContent, err := fs.fileSystem.Read(filePermission.Filepath)
		if err != nil {
			return nil, err
		}

		res, err := fs.guard.Decrypt(symmetricKey, fileContent)
		if err != nil {
			return nil, err
		}

		return &File{
			Filename: data.Filename,
			Content:  res,
		}, nil
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

func (fs *fileService) signFile(ctx context.Context, userId uint64, fileId uint64) error {
	// get file
	// if not found, return error
	file, err := fs.fileRepository.Get(ctx, fileId)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == pgx.ErrNoRows {
		return errors.New("Requested file not found")
	}

	// check user authority
	if userId != file.UserID {
		return errors.New("You do not have access to this resource data")
	}

	// check: if already signed, return error
	if file.IsSigned {
		return errors.New("Requested file already signed")
	}

	// get user
	user, err := fs.userService.GetUserWithRSA(ctx, userId)
	if err != nil {
		return err
	}

	// create signature metadata about the file and user
	signatureMetadata := SignatureMetadata{
		SignDate: time.Now(),
		SignBy:   user.Username,
		Contact:  user.Email,
	}

	// encrypt with private
	privateKey, err := fs.guard.ParsePrivateKey(user.PrivateKey)
	if err != nil {
		return err
	}

	byteSignatureMetadata, err := json.Marshal(signatureMetadata)
	if err != nil {
		return err
	}

	signature, err := fs.guard.SignRSA(privateKey, []byte(byteSignatureMetadata))
	if err != nil {
		return err
	}

	fullDataComment := []byte{}
	fullDataComment = append(fullDataComment, []byte("\n%"+DataCommentKey)...)
	fullDataComment = append(fullDataComment, byteSignatureMetadata...)

	fullSignatureComment := []byte{}
	fullSignatureComment = append(fullSignatureComment, []byte("\n%"+SignatureCommentKey)...)
	fullSignatureComment = append(fullSignatureComment, signature...)

	fullPublicKeyComment := []byte{}
	fullPublicKeyComment = append(fullPublicKeyComment, []byte("\n%"+PublicKeyCommentKey)...)
	fullPublicKeyComment = append(fullPublicKeyComment, []byte(user.PublicKey)...)

	// read file
	decryptedFile, err := fs.getFile(ctx, user.ID, fileId)
	if err != nil {
		return err
	}

	// append signature & public key to file
	fullFileContent := []byte{}
	fullFileContent = append(fullFileContent, decryptedFile.Content...)
	fullFileContent = append(fullFileContent, fullDataComment...)
	fullFileContent = append(fullFileContent, fullSignatureComment...)
	fullFileContent = append(fullFileContent, fullPublicKeyComment...)

	// encrypt file
	key, err := fs.guard.GetKey(ctx, fileTable, file.KeyReference)
	if err != nil {
		return err
	}

	// res, err := fs.guard.Encrypt(key, fileContent)
	res, err := fs.guard.Encrypt(key.PlainKey, fullFileContent)
	if err != nil {
		return err
	}

	// overwrite file content
	fs.fileSystem.Write(file.Filepath, res)

	// update file (is_signed: true) to db
	file.IsSigned = true
	err = fs.fileRepository.UpdateSignedStatus(ctx, file)
	if err != nil {
		return err
	}

	// TODO: handle duplicate file in sharing to other users

	return nil
}

func (fs *fileService) verifyFile(ctx context.Context, fileContent []byte) (SignatureMetadata, error) {

	// Parse file with tokens,
	// tokens in tokens should be by order of
	// the tokens inside the file.
	tokens := []string{
		"%" + DataCommentKey,
		"%" + SignatureCommentKey,
		"%" + PublicKeyCommentKey,
	}

	// the result follows the token content sequence
	results := [3]string{}

	// counter is a pointer to the token that is
	// going to be parsed
	ctr := 0

	// idx is a pointer to where the file is reading.
	idx := 0

	stringFileContent := string(fileContent)

	var buffer []byte
	for idx < len(stringFileContent) {
		if ctr <= 2 &&
			idx-len(stringFileContent[idx:idx+len(tokens[ctr])]) < len(stringFileContent) &&
			stringFileContent[idx:idx+len(tokens[ctr])] == tokens[ctr] {

			if ctr > 0 && len(buffer) > 0 {
				results[ctr-1] = string(buffer[:len(buffer)-1])
				buffer = []byte{}
			}

			idx += len(stringFileContent[idx : idx+len(tokens[ctr])])
			ctr++
		}

		if ctr > 0 {
			buffer = append(buffer, stringFileContent[idx])
		}

		if idx == len(stringFileContent)-1 {
			results[ctr-1] = string(buffer)
		}

		idx++
	}

	if ctr >= 3 {
		return SignatureMetadata{}, errors.New("signature invalid, it is incomplete")
	}

	pubKey, err := fs.guard.ParsePublicKey(results[2])
	if err != nil {
		return SignatureMetadata{}, err
	}

	var signatureMetadata SignatureMetadata

	err = json.Unmarshal([]byte(results[0]), &signatureMetadata)
	if err != nil {
		return SignatureMetadata{}, err
	}

	err = fs.guard.VerifyRSA(pubKey, []byte(results[1]), []byte(results[0]))
	if err != nil {
		return SignatureMetadata{}, err
	}

	return signatureMetadata, nil
}
