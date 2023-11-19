package permission

import "errors"

type RequestPermissionRequest struct {
	UserID         uint64
	TargetUsername string
}

type RequestPermissionResponse struct {
}

