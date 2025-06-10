package auth

import "context"

type handler struct {
	driver       Driver[any, any]
	userProvider UserProvider[any, any]
}

var _ UserRegisterer[any] = (*handler)(nil)

func (g *handler) Register(ctx context.Context, user any) (any, error) {
	if d, ok := g.userProvider.(UserRegisterer[any]); ok {
		return d.Register(ctx, user)
	}
	return nil, ErrUserRegisterNotSupported
}

func (g *handler) Authenticate(ctx context.Context, creds any) (any, error) {
	user, err := g.userProvider.FindByCredentials(ctx, creds)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (g *handler) Validate(ctx context.Context, proof any) (Verified[any], error) {
	verified, err := g.driver.Validate(ctx, proof)
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
