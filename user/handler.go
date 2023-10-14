package user

import (
	"context"
	"encoding/json"
	"net/http"
)

type UserService interface {
	register(ctx context.Context, request RegisterRequest) (*RegisterResponse, error)
	login(ctx context.Context, request LoginRequest) (*LoginResponse, error)
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
