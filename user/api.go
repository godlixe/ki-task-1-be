package user

import "errors"

type Response struct {
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type RegisterRequest struct {
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password" binding:"required"`
	Name        string `json:"name" binding:"required"`
	PhoneNumber string `json:"phone_number" binding:"required"`
	Gender      string `json:"gender" binding:"required,oneof=male female"`
	Religion    string `json:"religion" binding:"required"`
	Nationality string `json:"nationality" binding:"required"`
	Address     string `json:"address" binding:"required"`
	BirthInfo   string `json:"birth_info" binding:"required"`
}

func (rr *RegisterRequest) Validate() error {
	if rr.Gender != Male && rr.Gender != Female {
		return errors.New("Request invalid. Gender value must be male or female")
	}
	return nil
}

type RegisterResponse struct {
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type GetProfileRequest struct {
	UserID uint64 `binding:"required"`
}

type GetProfileResponse struct {
	Username    string `json:"username"`
	Name        string `json:"name"`
	PhoneNumber string `json:"phone_number"`
	Gender      string `json:"gender" binding:"required"`
	Religion    string `json:"religion"`
	Nationality string `json:"nationality"`
	Address     string `json:"address"`
	BirthInfo   string `json:"birth_info"`
}

type UpdateProfileRequest struct {
	UserID      uint64
	Username    string `json:"username" binding:"required"`
	Name        string `json:"name" binding:"required"`
	PhoneNumber string `json:"phone_number" binding:"required"`
	Gender      string `json:"gender" binding:"required,oneof=male female"`
	Religion    string `json:"religion" binding:"required"`
	Nationality string `json:"nationality" binding:"required"`
	Address     string `json:"address" binding:"required"`
	BirthInfo   string `json:"birth_info" binding:"required"`
}

func (rr *UpdateProfileRequest) Validate() error {
	if rr.Gender != Male && rr.Gender != Female {
		return errors.New("Request invalid. Gender value must be male or female")
	}
	return nil
}

type UpdateProfileResponse struct {
}
