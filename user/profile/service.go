package profile

import (
	"context"
	"encryption/guard"
	"encryption/user"
	"encryption/user/permission"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const userKeyTable = "user_keys"

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

type PermissionRepository interface {
	GetPermissionByUserId(context.Context, uint64, uint64) (*permission.Permission, error)
}

type profileService struct {
	userRepository       UserRepository
	permissionRepository PermissionRepository
	guard                guard.Guard
}

func NewProfileService(
	ur UserRepository,
	pr PermissionRepository,
	g guard.Guard,
) profileService {
	return profileService{
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

	if request.UserID != targetUser.ID {
		permission, err := ps.permissionRepository.GetPermissionByUserId(ctx, request.UserID, targetUser.ID)
		if err != nil && err != pgx.ErrNoRows {
			return nil, err
		}
		if permission == nil {
			return nil, fmt.Errorf("You do not have permission to access this %s data", request.TargetUsername)
		}
	}

	// TODO: check symmetric key using user private key (asymmetric encryption)

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
