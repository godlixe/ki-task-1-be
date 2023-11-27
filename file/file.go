package file

import (
	"encryption/guard"
	"errors"
)

// File represents a file entity.
type File struct {
	ID     uint64 `json:"id"`
	UserID uint64 `json:"user_id"`

	Filename string `json:"filename"`
	Type     string `json:"type"`
	Filepath string `json:"filepath,omitempty"`

	// Metadata is an encrypted reference to
	// the file's key.
	KeyReference []byte `json:"-"`

	// File content.
	Content []byte

	// Key represents the file's key
	Key guard.Key `json:"-"`
}

// Types for File.
const (
	IDCard         string = "id_card"
	ProfilePicture string = "profile_picture"
	Video          string = "video"
	Docs           string = "docs"
	Misc           string = "misc"
)

func ValidateType(s string) (string, error) {
	switch s {
	case "id_card":
		return IDCard, nil
	case "profile_picture":
		return ProfilePicture, nil
	case "video":
		return Video, nil
	case "docs":
		return Docs, nil
	case "misc":
		return Misc, nil
	}

	return "", errors.New("invalid type")
}
