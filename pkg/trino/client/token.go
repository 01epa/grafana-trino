package client

import (
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"time"
)

const UntilExpirationInSeconds = 60

type Token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	ExpiresAt   time.Time
}

func (token *Token) isAlmostExpired() bool {
	if token.AccessToken == "" {
		log.DefaultLogger.Info("Token is not yet retrieved")
		return true
	} else {
		if time.Now().Add(time.Second * time.Duration(UntilExpirationInSeconds)).After(token.ExpiresAt) {
			return true
		}
	}
	return false
}
