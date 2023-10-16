package user

import (
	"context"
	"encryption/guard"
	"encryption/helper"
	"errors"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
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
	GetById(context.Context, uint64) (*User, error)
	GetByUsername(context.Context, string) (*User, error)
	Create(context.Context, User) error
	Update(context.Context, User) error
}

type userService struct {
	userRepository UserRepository
	guard          guard.Guard
}

func NewFileService(
	ur UserRepository,
	g guard.Guard,
) userService {
	return userService{
		userRepository: ur,
		guard:          g,
	}
}

func (us *userService) login(ctx context.Context, request LoginRequest) (*LoginResponse, error) {
	user, err := us.userRepository.GetByUsername(ctx, request.Username)
	if err != nil {
		switch err {
		case pgx.ErrNoRows:
			return nil, errors.New("Username and/or password is wrong")
		default:
			return nil, errors.New("Token invalid")
		}
	}
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		switch err {
		case bcrypt.ErrMismatchedHashAndPassword:
			return nil, errors.New("Username and/or password is wrong")
		default:
			return nil, err
		}
	}

	// generate token
	accessToken, err := helper.GenerateAccessToken(user.ID)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		Token: accessToken,
	}, nil
}

func (us *userService) register(
	ctx context.Context,
	request RegisterRequest,
) (*RegisterResponse, error) {
	// find existing user with same username
	existingUser, err := us.userRepository.GetByUsername(ctx, request.Username)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	if existingUser != nil {
		return nil, errors.New("Username already exists")
	}

	cost, err := strconv.Atoi(os.Getenv("HASH_COST"))
	if err != nil {
		return nil, err
	}

	// generate hashed password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), cost)
	if err != nil {
		return nil, err
	}

	// create key
	key, err := us.guard.GenerateKey()
	if err != nil {
		return nil, err
	}

	user := User{
		Username:    request.Username,
		Password:    string(hashedPassword),
		Name:        request.Name,
		PhoneNumber: request.PhoneNumber,
		Gender:      request.Gender,
		Religion:    request.Religion,
		Nationality: request.Nationality,
		Address:     request.Address,
		BirthInfo:   request.BirthInfo,
	}

	// encrypt user data
	err = user.EncryptUserData(&us.guard, key)
	if err != nil {
		return nil, err
	}

	// store key to db
	metadata, err := us.guard.StoreKey(ctx, userKeyTable, guard.Key{
		PlainKey: key,
	})
	if err != nil {
		return nil, err
	}

	user.KeyReference = metadata

	err = us.userRepository.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	return &RegisterResponse{}, nil
}

func (us *userService) getProfile(
	ctx context.Context,
	request GetProfileRequest,
) (*GetProfileResponse, error) {
	user, err := us.userRepository.GetById(ctx, request.UserID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	key, err := us.guard.GetKey(ctx, userKeyTable, user.KeyReference)
	if err != nil {
		return nil, err
	}

	err = user.DecryptUserData(&us.guard, key)
	if err != nil {
		return nil, err
	}

	return &GetProfileResponse{
		Username:    user.Username,
		Name:        user.Name,
		PhoneNumber: user.PhoneNumber,
		Gender:      user.Gender,
		Religion:    user.Religion,
		Nationality: user.Nationality,
		Address:     user.Address,
		BirthInfo:   user.BirthInfo,
	}, nil
}

func (us *userService) updateProfile(
	ctx context.Context,
	request UpdateProfileRequest,
) (*UpdateProfileResponse, error) {
	existingUser, err := us.userRepository.GetById(ctx, request.UserID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}

	user := User{
		ID:           existingUser.ID,
		Username:     request.Username,
		Name:         request.Name,
		PhoneNumber:  request.PhoneNumber,
		Gender:       request.Gender,
		Religion:     request.Religion,
		Nationality:  request.Nationality,
		Address:      request.Address,
		BirthInfo:    request.BirthInfo,
		KeyReference: existingUser.KeyReference,
	}

	key, err := us.guard.GetKey(ctx, userKeyTable, user.KeyReference)
	if err != nil {
		return nil, err
	}

	err = user.EncryptUserData(&us.guard, key.PlainKey)
	if err != nil {
		return nil, err
	}

	err = us.userRepository.Update(ctx, user)
	if err != nil {
		return nil, err
	}

	return &UpdateProfileResponse{}, nil
}
