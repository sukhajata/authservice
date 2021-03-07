package keycloak

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/sukhajata/devicetwin/pkg/errorhelper"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// HTTPClient interface - represents http client
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	PostForm(url string, data url.Values) (*http.Response, error)
}

type Client struct {
	keycloakURL string
	realmID     string
	httpClient  HTTPClient
}

func NewClient(keycloakURL string, realmID string, httpClient HTTPClient) *Client {
	return &Client{
		keycloakURL: keycloakURL,
		realmID:     realmID,
		httpClient:  httpClient,
	}
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ContainerID string `json:"containerId"`
	ClientRole  bool   `json:"clientRole"`
	Composite   bool   `json:"composite"`
}

type User struct {
	Username    string        `json:"username"`
	Email       string        `json:"email"`
	Enabled     bool          `json:"enabled"`
	ID          string        `json:"id"`
	Credentials []Credentials `json:"credentials"`
}

type Credentials struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Keys struct {
	KeyData []Key `json:"keys"`
}

type Key struct {
	PublicKey string `json:"publicKey"`
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
}

func (c *Client) GetVerifyKey(username string, password string) (*rsa.PublicKey, error) {
	// get the keycloak public key
	// keep trying to connect
	numRetries := 0
	var verifyKey *rsa.PublicKey
	for {
		// get keycloak admin token
		adminToken, err := c.GetKeycloakToken(username, password, "admin-cli", "master")
		if err != nil {
			errorhelper.StartUpError(err)
			continue
		}

		// get public key
		publicKey, err := c.GetPublicKey(adminToken)
		if err != nil {
			errorhelper.StartUpError(err)
			numRetries++
			if numRetries > 5 {
				return nil, err
			}
			continue
		}
		// create pem
		pubKeyPem := []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", publicKey))

		// get rsa key from pem
		verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(pubKeyPem)
		if err != nil {
			panic(err)
		}
		break
	}

	return verifyKey, nil

}

// GetKeycloakToken - get a token from keycloak
func (c *Client) GetKeycloakToken(username string, password string, clientID string, realm string) (string, error) {
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)
	form.Add("grant_type", "password")
	form.Add("client_id", clientID)

	api := fmt.Sprintf("%srealms/%s/protocol/openid-connect/token", c.keycloakURL, realm)
	response, err := c.httpClient.PostForm(api, form)
	if err != nil {
		return "", err
	}

	if response.StatusCode == 401 {
		return "", fmt.Errorf("can not get token for user %s, please check keycloak config", username)
	}

	defer func() {
		err = response.Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	tokenResponse := TokenResponse{}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return "", err
	}

	if tokenResponse.AccessToken == "" {
		fmt.Println(body)
		return "", errors.New("failed to get token")
	}

	return tokenResponse.AccessToken, nil
}

// GetPublicKey - get the keycloak public key
func (c *Client) GetPublicKey(adminToken string) (string, error) {
	api := fmt.Sprintf("%sadmin/realms/%s/keys", c.keycloakURL, c.realmID)
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminToken))

	response, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() {
		err = response.Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	keys := Keys{}
	err = json.Unmarshal(body, &keys)
	if err != nil {
		return "", err
	}

	for _, v := range keys.KeyData {
		if v.Algorithm == "RS256" && v.Type == "RSA" {
			return v.PublicKey, nil
		}
	}

	return "", nil
}

// GetRoleID - get the id for a given role
func (c *Client) GetRoleID(realmID string, role string, token string) (string, error) {
	api := fmt.Sprintf("%sadmin/realms/%s/roles/%s", c.keycloakURL, realmID, role)
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	response, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() {
		err = response.Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	keycloakRole := Role{}
	err = json.Unmarshal(body, &keycloakRole)
	if err != nil {
		return "", err
	}

	return keycloakRole.ID, nil
}

// GetKeycloakUserID - get the id for a user
func (c *Client) GetKeycloakUserID(realmID string, username string, token string) (string, error) {
	api := fmt.Sprintf("%sadmin/realms/%s/users?username=%s", c.keycloakURL, realmID, username)
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	response, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() {
		err = response.Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	if response.StatusCode >= 300 {
		return "", fmt.Errorf("received response code %d", response.StatusCode)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	var users []User
	err = json.Unmarshal(body, &users)
	if err != nil {
		return "", err
	}

	if len(users) == 0 {
		return "", fmt.Errorf("user not found")
	}

	return users[0].ID, nil
}

// CreateKeycloakUser - create a keycloak user
func (c *Client) CreateKeycloakUser(realmID string, username string, email string, password string, token string) (string, error) {
	api := fmt.Sprintf("%sadmin/realms/%s/users", c.keycloakURL, realmID)

	creds := make([]Credentials, 1)
	creds[0] = Credentials{
		Type:  "password",
		Value: password,
	}
	user := &User{
		Email:       email,
		Enabled:     true,
		Username:    username,
		Credentials: creds,
	}

	jsonBytes, err := json.Marshal(user)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", api, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	if resp.StatusCode != 201 {
		return "", fmt.Errorf("response code %v", resp.StatusCode)
	}

	location := resp.Header.Get("location")
	if location == "" {
		return "", fmt.Errorf("no location header in response")
	}

	idx := strings.Index(location, "/users/")
	if idx <= 0 {
		return "", fmt.Errorf("could not find user id in %s", location)
	}
	userid := location[idx+7:]

	return userid, nil
}

// AddRoleToKeycloakUser - add the given role to the given user
func (c *Client) AddRoleToKeycloakUser(realmID string, userID string, role Role, token string) error {
	roles := make([]Role, 1)
	roles[0] = role
	jsonBytes, err := json.Marshal(roles)
	if err != nil {
		return err
	}

	api := fmt.Sprintf("%sadmin/realms/%s/users/%s/role-mappings/realm", c.keycloakURL, realmID, userID)
	req, err := http.NewRequest("POST", api, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("returned response code %v", resp.StatusCode)
	}

	return nil
}

// DeleteKeycloakUser deletes a user from keycloak
func (c *Client) DeleteKeycloakUser(userID string, adminToken string) error {
	api := fmt.Sprintf("%sadmin/realms/%s/users/%s", c.keycloakURL, c.realmID, userID)
	request, err := http.NewRequest("DELETE", api, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", fmt.Sprintf("bearer %s", adminToken))

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("returned response code %v", resp.StatusCode)
	}

	return nil
}
