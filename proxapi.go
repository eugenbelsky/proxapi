package proxapi

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

type Cluster struct {
	ApiUrl              string
	AuthTocken          string
	CSRFPreventionToken string
}

func (proxCluster *Cluster) GetAuthTocken(client *http.Client, username, password *string) error {

	apiPath := "/access/ticket"

	endpoint, err := url.ParseRequestURI(proxCluster.ApiUrl) // parse URI and enforce encoding

	if err != nil {
		return err
	}
	endpoint.Path = path.Join(endpoint.Path, apiPath) // construct request location

	loginPayload := url.Values{} // construct body
	loginPayload.Set("username", *username)
	loginPayload.Set("password", *password)

	request, err := http.NewRequest("POST", endpoint.String(), strings.NewReader(loginPayload.Encode())) // construct request

	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded") // assign required headers
	request.Header.Add("Content-Length", strconv.Itoa(len(loginPayload.Encode())))

	response, err := client.Do(request) // exec request
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return errors.New("Status Code " + strconv.Itoa(response.StatusCode))
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body) // read the body

	if err != nil {
		return err
	}

	proxCluster.AuthTocken = gjson.Get(string(body), "data.ticket").String()                       // assing authTocken to cluster
	proxCluster.CSRFPreventionToken = gjson.Get(string(body), "data.CSRFPreventionToken").String() // assign csrfPreventionToken to cluster

	return nil
}
func (proxCluster *Cluster) GetClusterStatus(client *http.Client) (string, error) {
	apiPath := "/cluster/status"

	endpoint, err := url.ParseRequestURI(proxCluster.ApiUrl) // parse URI and enforce encoding
	if err != nil {
		return "", err
	}
	endpoint.Path = path.Join(endpoint.Path, apiPath) // construct request location

	request, err := http.NewRequest("GET", endpoint.String(), nil) // construct request
	if err != nil {
		return "", err
	}

	request.Header.Add("Cookie", "PVEAuthCookie="+proxCluster.AuthTocken)      // assign authTocken header
	request.Header.Add("CSRFPreventionToken", proxCluster.CSRFPreventionToken) // assign csrf header

	response, err := client.Do(request) // exec request
	if err != nil {
		return "", err
	}

	if response.StatusCode != 200 {
		return "", errors.New("Status Code " + strconv.Itoa(response.StatusCode))
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body) // read the body

	if err != nil {
		return "", err
	}

	// statusJson := gjson.Get(string(body), "data").String()
	statusJson := string(body)
	return statusJson, nil
}
