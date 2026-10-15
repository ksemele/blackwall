package wazuh

import (
	"net/http"

	"github.com/ksemele/blackwall/internal/config"
	"github.com/ksemele/blackwall/internal/httpclient"
)

func buildHTTPClient(t config.TLS) (*http.Client, error) { return httpclient.New(t) }
