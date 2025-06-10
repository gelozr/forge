package auth

import "context"

type DefaultAuth[C, U, P any] struct {
	driver       Driver[U, P]
	userProvider UserProvider[C, U]
}

var _ AnyHandler = (*DefaultAuth[any, any, any])(nil)

func NewDefaultAuth[C, U, P any](userProvider UserProvider[C, U], driver Driver[U, P]) *DefaultAuth[C, U, P] {
	return &DefaultAuth[C, U, P]{
		driver:       driver,
		userProvider: userProvider,
	}
}

func (a *DefaultAuth[C, U, P]) Authenticate(ctx context.Context, creds C) (U, error) {
	user, err := a.userProvider.FindByCredentials(ctx, creds)
	if err != nil {
		return user, err
	}

	return user, nil
}

func (a *DefaultAuth[C, U, P]) Validate(ctx context.Context, proof P) (Verified[U], error) {
	verified, err := a.driver.Validate(ctx, proof)
	if err != nil {
		return Verified[U]{}, err
	}

	return verified, nil
}
