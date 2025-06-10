package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrJWTExpired          = errors.New("JWT is expired")
	ErrJWTInvalid          = errors.New("JWT is invalid")
	ErrRefreshTokenInvalid = errors.New("refresh token is used")
)

// type RefreshToken struct {
// 	ID        uuid.UUID
// 	UserID    uuid.UUID
// 	ExpiresAt time.Time
// 	Used      bool
// 	CreatedAt time.Time
// }
//
// type RefreshStore interface {
// 	Get(context.Context, uid string) (RefreshToken, error)
// 	Insert(context.Context, RefreshToken) (RefreshToken, error)
// 	Update(context.Context, RefreshToken) error
// }

type AccessToken struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

type Claims struct {
	UserID string
	jwt.RegisteredClaims
}

type JWTDriver struct {
	verifyKey []byte
}

var _ Driver[any, any] = (*JWTDriver)(nil)

func NewJWTDriver() *JWTDriver {
	return &JWTDriver{
		verifyKey: []byte("verifyKey"),
	}
}

func (d *JWTDriver) Sign(uid string) (string, time.Time, error) {
	exp := jwt.NewNumericDate(time.Now().Add(15 * time.Minute))

	c := Claims{}
	c.UserID = uid
	c.ID = uniqid()
	c.IssuedAt = jwt.NewNumericDate(time.Now())
	c.ExpiresAt = exp
	c.NotBefore = jwt.NewNumericDate(time.Now())

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	signed, err := tok.SignedString(d.verifyKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing token: %w", err)
	}

	return signed, exp.Time, nil
}

func (d *JWTDriver) Parse(tokenStr string) (Claims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		return d.verifyKey, nil
	})

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenSignatureInvalid), errors.Is(err, jwt.ErrTokenMalformed):
			return Claims{}, ErrJWTInvalid
		case errors.Is(err, jwt.ErrTokenExpired):
			return Claims{}, ErrJWTExpired
		default:
			return Claims{}, fmt.Errorf("parsing token: %w", err)
		}
	}

	if c, ok := tok.Claims.(Claims); ok {
		return c, nil
	}

	return Claims{}, ErrJWTInvalid
}

func (d *JWTDriver) IssueToken(ctx context.Context, usr any) (string, error) {
	u, ok := usr.(*User)
	if !ok {
		return "", errors.New("invalid user")
	}

	jwtStr, _, err := d.Sign(u.ID)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return jwtStr, nil
}

func (d *JWTDriver) Validate(ctx context.Context, payload any) (Verified[any], error) {
	token, ok := payload.(string)
	if !ok {
		return Verified[any]{}, errors.New("invalid jwt payload")
	}

	claims, err := d.Parse(token)
	if err != nil {
		return Verified[any]{}, fmt.Errorf("parse token: %w", err)
	}

	return Verified[any]{
		User: User{ID: claims.UserID},
	}, nil
}

// func (d *JWTDriver) RefreshToken(ctx context.Context, refreshToken string) (any, error) {
// 	refreshTokenID, err := uuid.Parse(refreshToken)
// 	if err != nil {
// 		return nil, ErrRefreshTokenInvalid
// 	}
//
// 	currRefresh, err := d.refreshSessionSvc.GetRefresh(ctx, refreshTokenID)
// 	if err != nil {
// 		return nil, fmt.Errorf("get refresh session: %w", err)
// 	}
//
// 	newRefresh, err := d.refreshSessionSvc.ExchangeRefresh(ctx, currRefresh)
// 	if err != nil {
// 		return nil, fmt.Errorf("exchange refresh: %w", err)
// 	}
//
// 	jwtStr, exp, err := d.Sign(newRefresh.UserID)
// 	if err != nil {
// 		return nil, fmt.Errorf("sign jwt: %w", err)
// 	}
//
// 	accessToken := AccessToken{
// 		AccessToken:  jwtStr,
// 		RefreshToken: newRefresh.ID.String(),
// 		ExpiresIn:    int(time.Until(exp).Seconds()),
// 	}
//
// 	return accessToken, nil
// }
