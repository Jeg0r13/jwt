package jwt

import (
	"auth/internal/entity"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"strconv"
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

type TokenWorker interface {
	GenerateToken(user entity.User, exp int64, secretKey string) (string, error)
	Validate(tokenString, secretKey string) error
	GetUserID(tokenString, secretKey string) (int64, error)
	GetExp(tokenString, secretKey string) (int64, error)
	GetEmail(tokenString, secretKey string) (string, error)
}

type tokenWorker struct{}

func NewJwtTokenWorker() TokenWorker {
	return &tokenWorker{}
}

func (w *tokenWorker) GenerateToken(user entity.User, exp int64, secretKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   user.ID,
		"email":     user.Email,
		"user_name": user.UserName,
		"is_admin":  user.IsAdmin,
		"exp":       exp,
	})
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (w *tokenWorker) Validate(tokenString, secretKey string) error {
	_, err := w.unParseToken(tokenString, secretKey)
	return err
}

func (w *tokenWorker) GetUserID(tokenString, secretKey string) (int64, error) {
	token, err := w.unParseToken(tokenString, secretKey)
	if err != nil {
		return 0, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, fmt.Errorf("unexpected type of claims %w", ErrInvalidToken)
	}
	userIDClaim, ok := claims["user_id"]
	if !ok {
		return 0, fmt.Errorf("token hasnt user_id claim %w", ErrInvalidToken)
	}
	userIDInt64, ok := userIDClaim.(int64)
	if ok {
		return userIDInt64, nil
	}
	userIDFloat64, ok := userIDClaim.(float64)
	if ok {
		return int64(userIDFloat64), nil
	}
	userIDString, ok := userIDClaim.(string)
	if ok {
		return strconv.ParseInt(userIDString, 10, 64)
	}
	return 0, fmt.Errorf("unexpected type of user_id claim %w", ErrInvalidToken)
}

func (w *tokenWorker) GetExp(tokenString, secretKey string) (int64, error) {
	token, err := w.unParseToken(tokenString, secretKey)
	if err != nil {
		return 0, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, fmt.Errorf("unexpected type of claims %w", ErrInvalidToken)
	}

	expClaim, ok := claims["exp"]
	if !ok {
		return 0, fmt.Errorf("token hasnt exp claim %w", ErrInvalidToken)
	}

	expInt64, ok := expClaim.(int64)
	if ok {
		return expInt64, nil
	}

	expFloat64, ok := expClaim.(float64)
	if ok {
		return int64(expFloat64), nil
	}

	expString, ok := expClaim.(string)
	if ok {
		return strconv.ParseInt(expString, 10, 64)
	}

	return 0, fmt.Errorf("unexpected type of exp claim %w", ErrInvalidToken)
}

func (w *tokenWorker) GetEmail(tokenString, secretKey string) (string, error) {
	token, err := w.unParseToken(tokenString, secretKey)
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("unexpected type of claims %w", ErrInvalidToken)
	}
	emailClaim, ok := claims["email"]
	if !ok {
		return "", fmt.Errorf("token hasnt email claim %w", ErrInvalidToken)
	}
	emailString, ok := emailClaim.(string)
	if !ok {
		return "", fmt.Errorf("unexpected type of email claim %w", ErrInvalidToken)
	}
	return emailString, nil
}

func (w *tokenWorker) unParseToken(tokenString, secretKey string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}
	return token, nil
}
