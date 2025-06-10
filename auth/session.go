package auth

import (
	"context"
	"fmt"
)

type SessionDriver[U, P any] interface {
	Driver[U, P]
	Login(ctx context.Context, user U) (P, error)
	Logout(ctx context.Context, sessionID P) error
}

type SessionAuth[C, U, P any] struct {
	DefaultAuth[C, U, P]
	driver SessionDriver[U, P]
}

var _ AnyHandler = (*SessionAuth[any, any, any])(nil)
var _ LoginHandler[any, any] = (*SessionAuth[any, any, any])(nil)
var _ LogoutHandler[any] = (*SessionAuth[any, any, any])(nil)

func NewSessionAuth[C, U, P any](driver SessionDriver[U, P], userProvider UserProvider[C, U]) *SessionAuth[C, U, P] {
	return &SessionAuth[C, U, P]{
		DefaultAuth: DefaultAuth[C, U, P]{
			userProvider: userProvider,
		},
		driver: driver,
	}
}

func (s *SessionAuth[C, U, P]) Attempt(ctx context.Context, creds C) (U, P, error) {
	var session P

	user, err := s.Authenticate(ctx, creds)
	if err != nil {
		return user, session, fmt.Errorf("authenticate: %w", err)
	}

	session, err = s.Login(ctx, user)
	if err != nil {
		return user, session, fmt.Errorf("login: %w", err)
	}

	return user, session, nil
}

func (s *SessionAuth[C, U, P]) Authenticate(ctx context.Context, creds C) (U, error) {
	return s.userProvider.FindByCredentials(ctx, creds)
}

func (s *SessionAuth[C, U, P]) Validate(ctx context.Context, sessionID P) (Verified[U], error) {
	return s.driver.Validate(ctx, sessionID)
}

func (s *SessionAuth[C, U, P]) Login(ctx context.Context, user U) (P, error) {
	return s.driver.Login(ctx, user)
}

func (s *SessionAuth[C, U, P]) Logout(ctx context.Context, sessionID P) error {
	return s.driver.Logout(ctx, sessionID)
}
