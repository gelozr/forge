package auth2

import "context"

type TokenDriver[U, P any] interface {
	Driver[U, P]
	IssueToken(ctx context.Context, user U) (P, error)
}

type TokenAuth[C, U, P any] struct {
	DefaultAuth[C, U, P]
	driver TokenDriver[U, P]
}

var _ AnyHandler = (*TokenAuth[any, any, any])(nil)
var _ TokenIssuer[any, any] = (*TokenAuth[any, any, any])(nil)
var _ TokenRefresher[any] = (*TokenAuth[any, any, any])(nil)
var _ TokenRevoker = (*TokenAuth[any, any, any])(nil)

func NewTokenAuth[C, U, P any](driver TokenDriver[U, P], userProvider UserProvider[C, U]) *TokenAuth[C, U, P] {
	return &TokenAuth[C, U, P]{
		DefaultAuth: DefaultAuth[C, U, P]{
			userProvider: userProvider,
		},
		driver: driver,
	}
}

func (t *TokenAuth[C, U, P]) Authenticate(ctx context.Context, creds C) (U, error) {
	return t.userProvider.FindByCredentials(ctx, creds)
}

func (t *TokenAuth[C, U, P]) Validate(ctx context.Context, token P) (Verified[U], error) {
	return t.driver.Validate(ctx, token)
}

func (t *TokenAuth[C, U, P]) IssueToken(ctx context.Context, user U) (P, error) {
	return t.driver.IssueToken(ctx, user)
}

func (t *TokenAuth[C, U, P]) RefreshToken(ctx context.Context, token string) (P, error) {
	if d, ok := t.driver.(TokenRefresher[P]); ok {
		return d.RefreshToken(ctx, token)
	}

	var zero P
	return zero, ErrRefreshTokenNotSupported
}

func (t *TokenAuth[C, U, P]) RevokeToken(ctx context.Context, token string) error {
	if d, ok := t.driver.(TokenRevoker); ok {
		return d.RevokeToken(ctx, token)
	}

	return ErrRevokeTokenNotSupported
}
