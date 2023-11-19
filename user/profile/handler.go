package profile

import (
	"context"
	"encoding/json"
	"encryption/helper"
	"net/http"
	"strings"
)

type ProfileService interface {
	getUserProfile(context.Context, GetUserProfileRequest) (*GetUserProfileResponse, error)
}

type Handler struct {
	profileService ProfileService
}

func NewUserHandler(
	ps profileService,
) Handler {
	return Handler{
		profileService: &ps,
	}
}

func (h *Handler) GetUserProfile(w http.ResponseWriter, r *http.Request) {
	var (
		request GetUserProfileRequest
		err     error
	)

	userId := uint64(r.Context().Value("user_id").(float64))
	targetUsername := strings.TrimPrefix(r.URL.Path, "/profile/")

	request.UserID = userId
	request.TargetUsername = targetUsername

	getProfileResponse, err := h.profileService.getUserProfile(context.TODO(), request)
	if err != nil {
		response := helper.Response{
			Message: err.Error(),
			Data:    nil,
		}

		jsonResponse, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResponse)
		return
	}

	response := helper.Response{
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
