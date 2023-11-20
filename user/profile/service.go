package profile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encryption/cache"
	"encryption/guard"
	"encryption/user"
	"encryption/user/permission"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const userKeyTable = "user_keys"
const permissionTable = "permission_keys"

type Guard interface {
	GetKey(table string, metadata []byte) (guard.Key, error)
	StoreKey(table string, key guard.Key) ([]byte, error)
	GenerateKey() ([]byte, error)
	Decrypt(key []byte, data []byte) ([]byte, error)
	Encrypt(key []byte, data []byte) ([]byte, error)
}

type UserRepository interface {
	GetByUsername(context.Context, string) (*user.User, error)
}

type UserService interface {
	GetUserWithRSA(
		ctx context.Context,
		userId uint64,
	) (*user.User, error)
}

type PermissionRepository interface {
	GetPermissionByUserId(context.Context, uint64, uint64) (*permission.Permission, error)
}

type profileService struct {
	redisClient          cache.RedisClient
	userService          UserService
	userRepository       UserRepository
	permissionRepository PermissionRepository
	guard                guard.Guard
}

func NewProfileService(
	rc cache.RedisClient,
	us UserService,
	ur UserRepository,
	pr PermissionRepository,
	g guard.Guard,
) profileService {
	return profileService{
		redisClient:          rc,
		userService:          us,
		userRepository:       ur,
		permissionRepository: pr,
		guard:                g,
	}
}

func (ps *profileService) getUserProfile(
	ctx context.Context,
	request GetUserProfileRequest,
) (*GetUserProfileResponse, error) {
	targetUser, err := ps.userRepository.GetByUsername(ctx, request.TargetUsername)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if targetUser == nil {
		return nil, errors.New("Username not found")
	}

	sourceUser, err := ps.userService.GetUserWithRSA(ctx, request.UserID)
	if err != nil {
		return nil, err
	}

	token := ctx.Value("user_token").(string)

	// check cache for permission
	permissionCache, err := ps.redisClient.Get(
		ctx,
		fmt.Sprintf("permission:%v_%v", token, targetUser.ID),
	)
	if err != nil {
		return nil, err
	}

	needAuth := true
	if len(permissionCache) >= 0 && string(permissionCache) == "true" {
		needAuth = false
	}

	if request.UserID != targetUser.ID && needAuth {
		permission, err := ps.permissionRepository.GetPermissionByUserId(ctx, request.UserID, targetUser.ID)
		if err != nil && err != pgx.ErrNoRows {
			return nil, err
		}
		if permission == nil {
			return nil, fmt.Errorf("You do not have permission to access this %s data", request.TargetUsername)
		}

		// get metadata key
		permissionKey, err := ps.guard.GetKey(ctx, permissionTable, permission.KeyReference)
		if err != nil {
			return nil, err
		}

		// decrypt permission key
		originalSymmetricKey, err := ps.guard.Decrypt(permissionKey.PlainKey, permission.Key)
		if err != nil {
			return nil, err
		}

		symmetricKey, err := base64.StdEncoding.DecodeString(request.Key)
		if err != nil {
			return nil, err
		}

		privateKey, err := ps.guard.ParsePrivateKey(sourceUser.PrivateKey)
		if err != nil {
			return nil, err
		}

		decryptedSymmetricKey, err := ps.guard.DecryptRSA(privateKey, symmetricKey)
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(originalSymmetricKey, decryptedSymmetricKey) {
			return nil, errors.New("access denied, key mismatch")
		}

		// set cache for permission

		err = ps.redisClient.Set(ctx,
			fmt.Sprintf("permission:%v_%v", token, targetUser.ID),
			"true",
		)
		if err != nil {
			return nil, err
		}
	}

	key, err := ps.guard.GetKey(ctx, userKeyTable, targetUser.KeyReference)
	if err != nil {
		return nil, err
	}

	err = targetUser.DecryptUserData(&ps.guard, key)
	if err != nil {
		return nil, err
	}

	return &GetUserProfileResponse{
		Username:    targetUser.Username,
		Name:        targetUser.Name,
		PhoneNumber: targetUser.PhoneNumber,
		Email:       targetUser.Email,
		Gender:      targetUser.Gender,
		Religion:    targetUser.Religion,
		Nationality: targetUser.Nationality,
		Address:     targetUser.Address,
		BirthInfo:   targetUser.BirthInfo,
	}, nil
}
