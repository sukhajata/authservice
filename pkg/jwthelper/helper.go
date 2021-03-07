package jwthelper

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type customClaims struct {
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	Username string `json:"preferred_username"`
	//overwrite audience from jtw.StandardClaims because it is type string and we need type string OR []string
	Audience multiString `json:"aud,omitempty"`
	*jwt.StandardClaims
}

type DataAPIClaims struct {
	Role string `json:"role"`
	User string `json:"user"`
	jwt.StandardClaims
}

type multiString string

// UnmarshalJSON - unmarshal []string into string
func (ms *multiString) UnmarshalJSON(data []byte) error {
	if len(data) > 0 {
		switch data[0] {
		case '"':
			var s string
			if err := json.Unmarshal(data, &s); err != nil {
				return err
			}
			*ms = multiString(s)
		case '[':
			var s []string
			if err := json.Unmarshal(data, &s); err != nil {
				return err
			}
			*ms = multiString(strings.Join(s, ","))
		}
	}
	return nil
}

// GetDataToken gets a token for accessing data api
func GetDataToken(secret string, username string) (string, error) {
	claims := &DataAPIClaims{
		Role: "web_user",
		User: username,
	}

	// Create a new token object, specifying signing method and the claims
	dataToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := dataToken.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// CheckJwt checks a jwt for validity and roles
func CheckJwt(token string, allowedRoles []string, verifyKey *rsa.PublicKey) (bool, string, string, error) {
	jwtToken, err := jwt.ParseWithClaims(token, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Check roles
		hasRole := false
		claims, _ := token.Claims.(*customClaims)
		roles := claims.RealmAccess.Roles
		if len(allowedRoles) == 0 {
			// no roles given
			return token, errors.New("no roles specified")
		} else {
			for _, i := range roles {
				for _, a := range allowedRoles {
					if i == a {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}
		}
		if !hasRole {
			return token, errors.New("user does not have required role")
		}

		// verify signature
		return verifyKey, nil
	})

	if err != nil {
		//check failed. return error message
		return false, "", err.Error(), nil
	}

	claims, ok := jwtToken.Claims.(*customClaims)
	if !ok {
		//check passed but can not get username
		return true, "", "OK", nil
	}

	return true, claims.Username, "OK", nil

}
