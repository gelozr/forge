package auth2

import (
	"context"
)

type Credentials = interface{}
type User = interface{}
type Payload = interface{}
type LoginID = interface{}

type Verified[U any] struct {
	User        U
	Permissions []string
}

type UserProvider[C, U any] interface {
	FindByCredentials(ctx context.Context, creds C) (U, error)
}

type Driver[U, P any] interface {
	Validate(ctx context.Context, proof P) (Verified[U], error)
}

type Handler[C, U, P any] interface {
	Authenticate(ctx context.Context, creds C) (U, error)
	Validate(ctx context.Context, payload P) (Verified[U], error)
}

type Authenticator[C, U any] interface {
	Authenticate(ctx context.Context, creds C) (U, error)
}

type Validator[U, P any] interface {
	Validate(ctx context.Context, payload P) (Verified[U], error)
}

type LoginHandler[U, R any] interface {
	Login(ctx context.Context, user U) (R, error)
}

type LogoutHandler[P any] interface {
	Logout(context.Context, P) error
}

type TokenIssuer[U, P any] interface {
	IssueToken(ctx context.Context, user U) (P, error)
}

type TokenRefresher[P any] interface {
	RefreshToken(ctx context.Context, refreshToken string) (P, error)
}

type TokenRevoker interface {
	RevokeToken(ctx context.Context, token string) error
}

type AnyHandler = Handler[any, any, any]

type Auth interface {
	Authenticate(ctx context.Context, creds any) (any, error)
	Validate(ctx context.Context, payload any) (Verified[any], error)
	Login(ctx context.Context, user any) (any, error)
	Logout(ctx context.Context, id any) error
	IssueToken(ctx context.Context, user any) (any, error)
	RefreshToken(ctx context.Context, refreshToken string) (any, error)
	RevokeToken(ctx context.Context, token string) error
	Handler(string) (AnyHandler, error)
	MustHandler(string) AnyHandler
}
