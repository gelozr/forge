package auth

import "github.com/google/uuid"

func uniqid() string {
	return uuid.NewString()
}
