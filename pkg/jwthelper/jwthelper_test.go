package jwthelper

import (
	"fmt"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestGetDataToken(t *testing.T) {
	dataServiceSecret := "M9D76Bfww30Lk2Jds723f2323r523f32"
	tokenString, err := GetDataToken(dataServiceSecret, "bob")
	assert.Nil(t, err)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("M9D76Bfww30Lk2Jds723f2323r523f32"), nil
	})

	if token.Valid {
		t.Log("Token valid")
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			t.Error("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			t.Error("token expired")
		} else {
			t.Error("couldn't handle this token:", err)
		}
	} else {
		t.Error("couldn't handle this token:", err)
	}
}

func TestCheckJwt(t *testing.T) {
	publicKey := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx7TIvDolcJOw+8tfR2GdsvrqAqf/x+o90Ur4a/Vq3sr1ow0/JGOtUpedfKKrO4hwm+G713RvyQI+mREGilaXfj6vitUVY9qeW/CdNLoZLjc2Bh+maZRgkeQcOypmgA4UZjwaI+ZanU3ajf8ZV7dc8/5Nwh9yg+xQLzeQp4L5JkJVo4zBJDDTVRQwAyEGNI9yNHbY5xzt8op3X8X/B46E6/M1J2XTz1l0wCEl9/yFQDIAOw139XXmd6iOVxeW2WKV2jZ3AGzvgzPmdjDzqH2WNXMug8rkYzXbndAcOMZPAasiyoCfeZ18qFUmDRloKx5cPRP3eyB00bnf8vLNZu06ywIDAQAB"
	pubKeyPem := []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", publicKey))

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyPem)
	if err != nil {
		t.Error(err)
	}

	token := "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrT3ktcEdTejhaT0h3QjExeUlxbks1Q2xBZW5tZUttT185eHZ5SHdHQm5BIn0.eyJleHAiOjE2MDU4MzQyODQsImlhdCI6MTYwNTgzMzk4NCwianRpIjoiZDY4NjNiNWQtZjAzNi00YTcyLWE2YWItYmM4NjQxNzIxZWVkIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrLWh0dHAuZGV2LnN2Yy9hdXRoL3JlYWxtcy9kZXZwb3dlciIsImF1ZCI6WyJyZWFjdC1hZG1pbiIsImFjY291bnQiXSwic3ViIjoiOTllZTg4ZDItMWRjMS00NzJjLTgyOWItNTNlMzFhZjcxZjRhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoicmVhY3QtaW5zdGFsbGVyIiwic2Vzc2lvbl9zdGF0ZSI6Ijc4ZDdjMDk3LTA5NDItNDRhMi1hOGM3LTc4NDZlZTIxMWM3ZiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2tleWNsb2FrLWh0dHAuZGV2LnN2YyIsImh0dHBzOi8vaW5zdGFsbGVyLmRldnBvd2VyLnBvd2VycGlsb3QubnoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbInBvd2VycGlsb3Qtc3VwZXJ1c2VyIiwicG93ZXJwaWxvdC1wcm9zdW1lciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJwb3dlcnBpbG90LWFkbWluIiwicG93ZXJwaWxvdC1pbnN0YWxsZXIiXX0sInJlc291cmNlX2FjY2VzcyI6eyJyZWFjdC1hZG1pbiI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctcHJvZmlsZSJdfSwicmVhY3QtaW5zdGFsbGVyIjp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50Iiwidmlldy1wcm9maWxlIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InRpbWMifQ.aW04NrcA_zaSbYHi__NjwIu7c9pS1n0YZZn01OFb7lmqm_pQaXaJq8ZLcNn9e2X6760ny17Hc7kZ26qf6iomgdyX7xZgvO4EDntx_hD8lD-ibcUl-Er5FLRNq58JoYUbz6LvgawgumfBCLyHoGy7A_P-illeKz4tv3VoQ6Yi2DaN_LynscYADB9PsgXxz5lU7P0UUvvYeuq62UrPZWiju2sZuZEFkyENTAqaPb24tbMDCAZt3oGQLtBGiEsuzOYRpOFLZigBbwftHphwG7aLQPg2uGy9ySSbwJyTVZtGzOjrgeIvgfPr1jvaWYQXmeB0iJj8tpy0cBmEMk11NI2Krg"
	allowedRoles := []string{
		"powerpilot-admin",
		"powerpilot-installer",
	}
	pass, username, _, err := CheckJwt(token, allowedRoles, verifyKey)
	assert.Nil(t, err)
	assert.False(t, pass)
	t.Log(username)
}
