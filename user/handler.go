package user

import (
	"context"
	"encoding/json"
	"net/http"
)

type UserService interface {
	register(ctx context.Context, request RegisterRequest) (*RegisterResponse, error)
	login(ctx context.Context, request LoginRequest) (*LoginResponse, error)
	getProfile(ctx context.Context, request GetProfileRequest) (*GetProfileResponse, error)
	updateProfile(ctx context.Context, request UpdateProfileRequest) (*UpdateProfileResponse, error)
}

type Handler struct {
	userService UserService
}

func NewUserHandler(
	us userService,
) Handler {
	return Handler{
		userService: &us,
	}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var (
		request LoginRequest
		err     error
	)

	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	loginResponse, err := h.userService.login(context.TODO(), request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := Response{
		Data:    loginResponse,
		Message: "Login success",
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonResponse)
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var (
		request RegisterRequest
		err     error
	)

	if err = json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err = request.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err = h.userService.register(context.TODO(), request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := Response{
		Message: "User successfully registered",
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonResponse)
}

func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	var (
		request GetProfileRequest
		err     error
	)

	userId := uint64(r.Context().Value("user_id").(float64))

	request.UserID = userId

	getProfileResponse, err := h.userService.getProfile(context.TODO(), request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := Response{
		Data:    getProfileResponse,
		Message: "Get profile success",
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(jsonResponse))
}

func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	var (
		request UpdateProfileRequest
		err     error
	)

	if err = json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err = request.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userId := uint64(r.Context().Value("user_id").(float64))
	request.UserID = userId

	_, err = h.userService.updateProfile(context.TODO(), request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := Response{
		Message: "Update profile success",
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(jsonResponse))
}