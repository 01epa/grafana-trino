package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var (
	lock  = &sync.Mutex{}
	token *Token
)

type TrinoClient struct {
	*http.Client
	ClientId          string
	ClientSecret      string
	Url               string
	ImpersonationUser string
}

func (c *TrinoClient) Do(req *http.Request) (*http.Response, error) {
	log.DefaultLogger.Info("Add token to request")
	token, err := c.getToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	if c.ImpersonationUser != "" {
		req.Header.Set("X-Trino-User", c.ImpersonationUser)
	}
	return c.Client.Do(req)
}

func (c *TrinoClient) getToken() (*Token, error) {
	if token == nil || token.isAlmostExpired() {
		lock.Lock()
		defer lock.Unlock()
		if token == nil || token.isAlmostExpired() {
			newToken, err := c.retrieveToken()
			if err != nil {
				log.DefaultLogger.Info("Cannot get token:", "error", err)
				return nil, err
			} else {
				token = newToken
			}
		}
	}
	return token, nil
}

func (c *TrinoClient) retrieveToken() (*Token, error) {
	log.DefaultLogger.Info("Try retrieve token")
	values := url.Values{
		"client_id":     []string{c.ClientId},
		"client_secret": []string{c.ClientSecret},
		"grant_type":    []string{"client_credentials"},
	}

	token := &Token{}
	response, err := c.PostForm(c.Url, values)
	if err == nil {
		if response.StatusCode == 200 {
			var jsonResponse []byte
			if jsonResponse, err = io.ReadAll(response.Body); err == nil {
				defer response.Body.Close()
				err = json.Unmarshal(jsonResponse, token)
				token.ExpiresAt = time.Now().Add(time.Second * time.Duration(token.ExpiresIn))
				log.DefaultLogger.Info("Token will expire at:", "date", token.ExpiresAt.Format(time.RFC1123Z))
				return token, err
			} else {
				defer response.Body.Close()
				log.DefaultLogger.Error("Error parsing token response from IDP:", "error", err)
				return nil, err
			}
		} else {
			message := fmt.Sprintf("Cannot obtain token from IDP. Received '%s' status code in response", response.Status)
			log.DefaultLogger.Error(message)
			err = errors.New(message)
			return nil, err
		}
	} else {
		log.DefaultLogger.Error("Error sending token request to IDP:", "error", err)
		return nil, err
	}
}
