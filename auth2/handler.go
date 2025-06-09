package auth2

import "context"

type handler struct {
	driver       Driver[any, any]
	userProvider UserProvider[any, any]
}

func (g *handler) Authenticate(ctx context.Context, creds any) (any, error) {
	user, err := g.userProvider.FindByCredentials(ctx, creds)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (g *handler) Validate(ctx context.Context, payload any) (Verified[any], error) {
	verified, err := g.driver.Validate(ctx, payload)
	if err != nil {
		return Verified[any]{}, err
	}

	return verified, nil
}

func (g *handler) Login(ctx context.Context, user any) (any, error) {
	if d, ok := g.driver.(LoginHandler[any, any]); ok {
		return d.Login(ctx, user)
	}
	return nil, ErrLoginNotSupported
}

func (g *handler) Logout(ctx context.Context, id any) error {
	if d, ok := g.driver.(LogoutHandler[any]); ok {
		return d.Logout(ctx, id)
	}
	return ErrLogoutNotSupported
}

func (g *handler) IssueToken(ctx context.Context, user any) (any, error) {
	if d, ok := g.driver.(TokenIssuer[any, any]); ok {
		return d.IssueToken(ctx, user)
	}
	return nil, ErrIssueTokenNotSupported
}

func (g *handler) RefreshToken(ctx context.Context, refreshToken string) (any, error) {
	if d, ok := g.driver.(TokenRefresher[any]); ok {
		return d.RefreshToken(ctx, refreshToken)
	}
	return nil, ErrRefreshTokenNotSupported
}
