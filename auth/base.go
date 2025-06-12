package auth

import "context"

// BaseAuth provides a reusable, generic authentication handler.
// It connects a user provider and a driver to support basic
// authentication and identity validation.
//
// C - Credential type (e.g., struct with email/password)
// U - User type
// P - Proof type (e.g., token, session ID)
type BaseAuth[C, U, P any] struct {
	driver       Validator[U, P]    // Responsible for validating the proof (e.g., token/session ID)
	userProvider UserProvider[C, U] // Responsible for locating and authenticating users by credentials
}

var _ AnyHandler = (*BaseAuth[any, any, any])(nil)

// NewBaseAuth creates a new BaseAuth instance with the provided
// user provider and driver.
func NewBaseAuth[C, U, P any](userProvider UserProvider[C, U], driver Validator[U, P]) *BaseAuth[C, U, P] {
	return &BaseAuth[C, U, P]{
		driver:       driver,
		userProvider: userProvider,
	}
}

// Authenticate attempts to find and return a user based on the
// provided credentials. Delegates to the UserProvider.
func (a *BaseAuth[C, U, P]) Authenticate(ctx context.Context, creds C) (U, error) {
	return a.userProvider.FindByCredentials(ctx, creds)
}

// Validate checks the authenticity of a proof (e.g., token/session ID)
// and returns the verified user context. Delegates to the Validator.
func (a *BaseAuth[C, U, P]) Validate(ctx context.Context, proof P) (Verified[U], error) {
	return a.driver.Validate(ctx, proof)
}
