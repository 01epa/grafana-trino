package driver

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	trinoClient "github.com/trinodb/grafana-trino/pkg/trino/client"
	"net/http"

	"github.com/trinodb/grafana-trino/pkg/trino/models"
	"github.com/trinodb/trino-go-client/trino"
	_ "github.com/trinodb/trino-go-client/trino"
)

const DriverName string = "trino"

type customTransport struct {
	client *trinoClient.TrinoClient
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.client.Do(req)
}

// Open registers a new driver with a unique name
func Open(settings models.TrinoDatasourceSettings) (*sql.DB, error) {
	skipVerify := false
	var certPool *x509.CertPool
	var clientCert []tls.Certificate
	if settings.Opts.TLS != nil {
		skipVerify = settings.Opts.TLS.InsecureSkipVerify
		if settings.Opts.TLS.CACertificate != "" {
			certPool := x509.NewCertPool()
			certPool.AppendCertsFromPEM([]byte(settings.Opts.TLS.CACertificate))
		}
		if settings.Opts.TLS.ClientCertificate != "" {
			if settings.Opts.TLS.ClientKey == "" {
				return nil, errors.New("client certificate was configured without a client key")
			}
			cert, err := tls.X509KeyPair(
				[]byte(settings.Opts.TLS.ClientCertificate),
				[]byte(settings.Opts.TLS.ClientKey))
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			clientCert = append(clientCert, cert)
		}
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
				Certificates:       clientCert,
				RootCAs:            certPool,
			},
		},
	}
	if settings.TokenUrl != "" && settings.ClientId != "" && settings.ClientSecret != "" {
		client = &http.Client{
			Transport: &customTransport{
				client: &trinoClient.TrinoClient{
					Client:            client,
					ClientId:          settings.ClientId,
					ClientSecret:      settings.ClientSecret,
					Url:               settings.TokenUrl,
					ImpersonationUser: settings.ImpersonationUser,
				},
			},
		}
	}
	err := trino.RegisterCustomClient("grafana", client)
	if err != nil {
		return nil, err
	}
	config := trino.Config{
		ServerURI:                  settings.URL.String(),
		Source:                     "grafana",
		CustomClientName:           "grafana",
		ForwardAuthorizationHeader: true,
		AccessToken:                settings.AccessToken,
	}

	dsn, err := config.FormatDSN()
	if err != nil {
		return nil, err
	}
	return sql.Open(DriverName, dsn)
}
