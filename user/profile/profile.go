package profile

type GetUserProfileRequest struct {
	UserID         uint64 `binding:"required"`
	TargetUsername string `binding:"required"`
	Key            string `json:"key" binding:"required"`
}

type GetUserProfileResponse struct {
	Username    string `json:"username"`
	Name        string `json:"name"`
	PhoneNumber string `json:"phone_number"`
	Email       string `json:"email"`
	Gender      string `json:"gender" binding:"required"`
	Religion    string `json:"religion"`
	Nationality string `json:"nationality"`
	Address     string `json:"address"`
	BirthInfo   string `json:"birth_info"`
}
