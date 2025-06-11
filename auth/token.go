package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrJWTExpired = errors.New("JWT is expired")
	ErrJWTInvalid = errors.New("JWT is invalid")
)

// TokenDriver defines the contract for token-based authentication drivers.
// U is the user type, P is the token type (e.g., string or JWT container).
// Drivers must implement Validate (from Driver), and IssueToken to generate tokens.
type TokenDriver[U, P any] interface {
	Driver[U, P]
	IssueToken(ctx context.Context, user U) (P, error)
}

// TokenAuth is a generic authentication handler for token-based flows.
// It embeds BaseAuth for Authenticate/Validate, and adds token issuance,
// refresh, and revocation capabilities via TokenDriver.
//
// C - credential type for Authenticate (e.g., login form struct)
// U - user type returned by Authenticate
// P - token type used by Validate and IssueToken
type TokenAuth[C, U, P any] struct {
	BaseAuth[C, U, P]
	driver TokenDriver[U, P]
}

// Compile-time checks that TokenAuth implements the dynamic handler interfaces.
var (
	_ AnyHandler            = (*TokenAuth[any, any, any])(nil)
	_ TokenIssuer[any, any] = (*TokenAuth[any, any, any])(nil)
	_ TokenRefresher[any]   = (*TokenAuth[any, any, any])(nil)
	_ TokenRevoker          = (*TokenAuth[any, any, any])(nil)
)

// NewTokenAuth constructs a new TokenAuth with the given TokenDriver and UserProvider.
func NewTokenAuth[C, U, P any](driver TokenDriver[U, P], userProvider UserProvider[C, U]) *TokenAuth[C, U, P] {
	return &TokenAuth[C, U, P]{
		BaseAuth: BaseAuth[C, U, P]{userProvider: userProvider},
		driver:   driver,
	}
}

// Validate delegates proof validation to the token driver, returning a Verified user.
func (t *TokenAuth[C, U, P]) Validate(ctx context.Context, token P) (Verified[U], error) {
	return t.driver.Validate(ctx, token)
}

// IssueToken delegates token creation to the token driver for the given user.
func (t *TokenAuth[C, U, P]) IssueToken(ctx context.Context, user U) (P, error) {
	return t.driver.IssueToken(ctx, user)
}

// RefreshToken checks if the driver supports token refreshing and delegates to it.
// Returns ErrRefreshTokenNotSupported if unsupported.
func (t *TokenAuth[C, U, P]) RefreshToken(ctx context.Context, token string) (P, error) {
	if d, ok := t.driver.(TokenRefresher[P]); ok {
		return d.RefreshToken(ctx, token)
	}

	var zero P
	return zero, ErrRefreshTokenNotSupported
}

// RevokeToken checks if the driver supports token revocation and delegates to it.
// Returns ErrRevokeTokenNotSupported if unsupported.
func (t *TokenAuth[C, U, P]) RevokeToken(ctx context.Context, token string) error {
	if d, ok := t.driver.(TokenRevoker); ok {
		return d.RevokeToken(ctx, token)
	}

	return ErrRevokeTokenNotSupported
}

// Claims represents the JWT payload structure used by JWTDriver.
type Claims struct {
	UserID string
	jwt.RegisteredClaims
}

// JWTDriver is a simple JWT-based TokenDriver implementation.
// It signs and parses JWTs using an HMAC verify key.
type JWTDriver struct {
	verifyKey []byte
}

// Compile-time checks that JWTDriver implements the Driver and TokenIssuer interfaces.
var _ Driver[any, any] = (*JWTDriver)(nil)
var _ TokenIssuer[any, any] = (*JWTDriver)(nil)

// NewJWTDriver creates a JWTDriver with a default HMAC verify key.
// In production, replace with secure key management.
func NewJWTDriver() *JWTDriver {
	return &JWTDriver{
		verifyKey: []byte("verifyKey"),
	}
}

// Sign generates a signed JWT string and returns its expiration time.
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

// Parse validates and decodes a JWT string into Claims.
// It maps JWT parsing errors to ErrJWTInvalid or ErrJWTExpired.
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

	if c, ok := tok.Claims.(*Claims); ok {
		return *c, nil
	}

	return Claims{}, ErrJWTInvalid
}

// IssueToken creates a JWT for the given user (expected as *User).
// Implements the TokenIssuer interface.
func (d *JWTDriver) IssueToken(ctx context.Context, usr any) (any, error) {
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

// Validate parses and validates the JWT, returning a Verified[any] with the user.
// Implements the Driver interface.
func (d *JWTDriver) Validate(ctx context.Context, proof any) (Verified[any], error) {
	token, ok := proof.(string)
	if !ok {
		return Verified[any]{}, ErrJWTInvalid
	}

	claims, err := d.Parse(token)
	if err != nil {
		return Verified[any]{}, fmt.Errorf("parse token: %w", err)
	}

	return Verified[any]{
		User: &User{ID: claims.UserID},
	}, nil
}
