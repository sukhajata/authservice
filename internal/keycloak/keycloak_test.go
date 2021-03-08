package keycloak_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/sukhajata/authservice/internal/keycloak"
	"github.com/sukhajata/authservice/mocks"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient_GetKeycloakToken_InvalidUser(t *testing.T) {
	// setup
	httpClient := &mocks.MockHTTPClient{
		Response: &http.Response{
			StatusCode: 401,
		},
		Error: fmt.Errorf("can not get token for user, please check keycloak config"),
	}
	keycloakClient := keycloak.NewClient("http://keycloak.installation", "test", httpClient)

	// call
	token, err := keycloakClient.GetKeycloakToken("intruder", "manchester_rulz", "powerpilot-installer", "devpower")

	// assert
	assert.NotNil(t, err)
	assert.EqualValues(t, token, "")
	t.Log("received 401 as expected for invalid credentials")
}

func TestClient_GetKeycloakToken(t *testing.T) {
	// build response JSON
	json := `{"access_token":"1234"}`
	// create a new reader with that JSON
	r := ioutil.NopCloser(bytes.NewReader([]byte(json)))

	httpClient := &mocks.MockHTTPClient{
		Response: &http.Response{
			StatusCode: 200,
			Body:       r,
		},
		Error: nil,
	}
	keycloakClient := keycloak.NewClient("http://keycloak.installation", "test", httpClient)

	// call
	token, err := keycloakClient.GetKeycloakToken("timc", "132731", "powerpilot-installer", "devpower")

	// assert
	assert.Nil(t, err)
	assert.EqualValues(t, "1234", token)
	t.Log("received token as expected")
}

func TestClient_GetPublicKey(t *testing.T) {
	// setup
	key := keycloak.Key{
		PublicKey: "public_key",
		Type:      "RSA",
		Algorithm: "RS256",
	}
	keys := keycloak.Keys{
		KeyData: []keycloak.Key{key},
	}
	data, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}

	r := ioutil.NopCloser(bytes.NewReader(data))

	httpClient := &mocks.MockHTTPClient{
		Response: &http.Response{
			StatusCode: 200,
			Body:       r,
		},
		Error: nil,
	}
	keycloakClient := keycloak.NewClient("http://keycloak.installation", "test", httpClient)

	// call
	public_key, err := keycloakClient.GetPublicKey("1234")

	// assert
	assert.Nil(t, err)
	assert.EqualValues(t, "public_key", public_key)
	t.Log("Received public key as expected")
}

func TestClient_GetRoleID(t *testing.T) {
	// setup
	role := keycloak.Role{
		ID:          "1234",
		Name:        "powerpilot-role",
		ContainerID: "container",
		ClientRole:  false,
		Composite:   false,
	}
	data, err := json.Marshal(role)
	if err != nil {
		t.Fatal(err)
	}

	r := ioutil.NopCloser(bytes.NewReader(data))

	httpClient := &mocks.MockHTTPClient{
		Response: &http.Response{
			StatusCode: 200,
			Body:       r,
		},
		Error: nil,
	}
	keycloakClient := keycloak.NewClient("http://keycloak.installation", "test", httpClient)

	// call
	roleID, err := keycloakClient.GetRoleID("devpower", "powerpilot-installer", "1234")

	// assert
	assert.Nil(t, err)
	assert.EqualValues(t, "1234", roleID)
	t.Log("Received role id as expected")
}

func TestClient_GetKeycloakUserID(t *testing.T) {
	// setup
	creds := make([]keycloak.Credentials, 1)
	creds[0] = keycloak.Credentials{
		Type:  "password",
		Value: "123",
	}
	users := make([]keycloak.User, 1)
	users[0] = keycloak.User{
		Username:    "timc",
		Email:       "email.com",
		Enabled:     true,
		ID:          "4321",
		Credentials: creds,
	}

	data, err := json.Marshal(users)
	if err != nil {
		t.Fatal(err)
	}

	r := ioutil.NopCloser(bytes.NewReader(data))

	httpClient := &mocks.MockHTTPClient{
		Response: &http.Response{
			StatusCode: 200,
			Body:       r,
		},
		Error: nil,
	}
	keycloakClient := keycloak.NewClient("http://keycloak.installation", "test", httpClient)

	// call
	userID, err := keycloakClient.GetKeycloakUserID("devpower", "timc", "1234")

	// assert
	assert.Nil(t, err)
	assert.EqualValues(t, "4321", userID)
	t.Log("Received user id as expected")
}

func TestClient_CreateKeycloakUser(t *testing.T) {
	// build response JSON
	json := `{"dummy":"OK"}`
	// create a new reader with that JSON
	r := ioutil.NopCloser(bytes.NewReader([]byte(json)))

	response := &http.Response{
		StatusCode: 201,
		Body:       r,
		Header:     http.Header{},
	}
	response.Header.Set("location", "realm/users/1234")
	httpClient := &mocks.MockHTTPClient{
		Response: response,
		Error:    nil,
	}
	keycloakClient := keycloak.NewClient("http://keycloak.installation", "test", httpClient)

	// call
	userID, err := keycloakClient.CreateKeycloakUser("devpower", "timc", "email.com", "1234", "1234")
	assert.Nil(t, err)
	assert.EqualValues(t, "1234", userID)
	t.Log("Received user id as expected")
}

func TestClient_AddRoleToKeycloakUser(t *testing.T) {
	// build response JSON
	json := `{"dummy":"OK"}`
	// create a new reader with that JSON
	r := ioutil.NopCloser(bytes.NewReader([]byte(json)))

	response := &http.Response{
		StatusCode: 200,
		Body:       r,
	}

	httpClient := &mocks.MockHTTPClient{
		Response: response,
		Error:    nil,
	}
	keycloakClient := keycloak.NewClient("http://keycloak.installation", "test", httpClient)

	role := keycloak.Role{
		ID:          "1234",
		Name:        "powerpilot-role",
		ContainerID: "container",
		ClientRole:  false,
		Composite:   false,
	}

	// call
	err := keycloakClient.AddRoleToKeycloakUser("1234", "1234", role, "1234")

	// assert
	assert.Nil(t, err)
	t.Log("Added role to keycloak user")
}
