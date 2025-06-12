package auth

import (
	"context"
)

// Verified holds the result of a successful proof validation,
// containing the authenticated user and optional permissions.
type Verified[U any] struct {
	User        U
	Permissions []string
}

// UserProvider represents a user lookup service using provided credentials.
type UserProvider[C, U any] interface {
	FindByCredentials(ctx context.Context, creds C) (U, error)
}

// Authenticator defines a single responsibility interface for authenticating users
// using provided credentials.
type Authenticator[C, U any] interface {
	Authenticate(ctx context.Context, creds C) (U, error)
}

// Validator defines a component capable of validating a proof (e.g., token, session ID)
// and returning a verified user context.
type Validator[U, P any] interface {
	Validate(ctx context.Context, proof P) (Verified[U], error)
}

// Handler is a generic interface that combines authentication and validation
// behavior using a credential and proof system.
type Handler[C, U, P any] interface {
	Authenticate(ctx context.Context, creds C) (U, error)
	Validate(ctx context.Context, proof P) (Verified[U], error)
}

// UserRegisterer defines a contract for registering new users.
type UserRegisterer[U any] interface {
	Register(context.Context, U) (U, error)
}

// LoginHandler defines an interface for logging in a user and returning a session ID.
type LoginHandler[U any] interface {
	Login(ctx context.Context, user U) (string, error)
}

// LogoutHandler defines an interface for logging out a user by session ID.
type LogoutHandler interface {
	Logout(context.Context, string) error
}

// TokenIssuer defines an interface for issuing tokens for a given user.
type TokenIssuer[U, P any] interface {
	IssueToken(ctx context.Context, user U) (P, error)
}

// TokenRefresher defines an interface for refreshing tokens using a refresh token string.
type TokenRefresher[P any] interface {
	RefreshToken(ctx context.Context, refreshToken string) (P, error)
}

// TokenRevoker defines an interface for explicitly revoking a token.
type TokenRevoker interface {
	RevokeToken(ctx context.Context, token string) error
}

// AnyHandler is a convenience alias for a fully dynamic, untyped handler.
type AnyHandler = Handler[any, any, any]

// Auth defines the top-level dynamic contract for interacting with authentication
// mechanisms. This is used by the Manager or global functions.
//
// All methods are dynamic and rely on runtime type assertions.
type Auth interface {
	Register(ctx context.Context, user any) (any, error)
	Authenticate(ctx context.Context, creds any) (any, error)
	Validate(ctx context.Context, proof any) (Verified[any], error)
	Login(ctx context.Context, user any) (string, error)
	Logout(ctx context.Context, sessionID string) error
	IssueToken(ctx context.Context, user any) (any, error)
	RefreshToken(ctx context.Context, refreshToken string) (any, error)
	RevokeToken(ctx context.Context, token string) error
	LookupHandler(string) (AnyHandler, error)
	MustHandler(string) AnyHandler
}
