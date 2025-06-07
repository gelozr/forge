package auth

import (
	"context"
)

type Credentials interface{}

type User interface {
	UserID() any
}

type UserProvider interface {
	FindByCredentials(context.Context, Credentials) (User, error)
}

type Driver interface {
	// Validate verifies the payload or token signature of its specific driver
	Validate(ctx context.Context, payload any) (Verified, error)
}

type TokenIssuer interface {
	IssueToken(ctx context.Context, user User) (any, error)
}
type TokenRefresher interface {
	RefreshToken(ctx context.Context, refreshToken string) (any, error)
}

type Authenticator interface {
	Authenticate(ctx context.Context, creds Credentials) (User, error)
}

type LoginHandler interface {
	Login(ctx context.Context, user User) (any, error)
}

type LogoutHandler interface {
	Logout(ctx context.Context, id any) error
}

type Checker interface {
	Check(ctx context.Context, payload any) (Verified, error)
}

type Guard interface {
	Authenticate(ctx context.Context, creds Credentials) (User, error)
	Login(ctx context.Context, user User) (any, error)
	Logout(ctx context.Context, id any) error
	Check(ctx context.Context, payload any) (Verified, error)
	RefreshToken(ctx context.Context, refreshToken string) (any, error)
}

type Auth interface {
	Authenticate(ctx context.Context, creds Credentials) (User, error)
	Login(ctx context.Context, user User) (any, error)
	Logout(ctx context.Context, id any) error
	Check(ctx context.Context, payload any) (Verified, error)
	RefreshToken(ctx context.Context, refreshToken string) (any, error)
	Guard(string) (Guard, error)
	MustGuard(string) Guard
}
