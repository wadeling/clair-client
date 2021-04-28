package clair

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/wadeling/clair-client/pkg/model"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	postLayerURI        = "http://%s:%d/v1/layers"
	getLayerFeaturesURI = "http://%s:%d/v1/layers/%s?vulnerabilities"
)

type Client struct {
	clairAddr string
	clairPort int
}

func (c *Client) scheduleLayerScanInClair(ctx context.Context, path, layerName, parentLayerName string) error {
	payload := NewerLayerEnvelope{
		Layer: NewerLayer{
			Name:       layerName,
			Path:       path,
			ParentName: parentLayerName,
			Format:     "Docker",
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("json marshal err %v",err)
	}

	reqPath := fmt.Sprintf(postLayerURI, c.clairAddr, c.clairPort)
	request, err := http.NewRequest("POST", reqPath, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("new request err %v",err)
	}
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("http client request err %v",err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("read clair response err.%d,%v",response.StatusCode,err)
		}

		if response.StatusCode >= 300 {
			clairResponseError := &NewerLayerEnvelope{}
			err := json.Unmarshal(body, clairResponseError)
			if err != nil {
				return fmt.Errorf("json unmarshal clair response err %v",err)
			}

			if response.StatusCode == http.StatusBadRequest {
				if strings.Contains(clairResponseError.Error.Message, "parent layer is unknown") {
					return fmt.Errorf("clair response not found layer err %s",clairResponseError.Error.Message)
				}
			}

			if response.StatusCode == http.StatusUnprocessableEntity {
				// Possible cause: "worker: OS and/or package manager are not supported"
				return fmt.Errorf("clair response err:%d %s",response.StatusCode,clairResponseError.Error.Message)
			}
		}

		return fmt.Errorf("expected clair return 201,but get %d,body %v",response.StatusCode,body)
	}

	return nil
}

func (c *Client) getTransformedLayerScanResultFromClair(ctx context.Context, digest string) (string, []model.VulnerabilityInfo, error) {
	var vulnerabilities = make([]model.VulnerabilityInfo, 0)
	var vulnerabilitiesMap = make(map[string]model.VulnerabilityInfo)
	rawVulnerabilities, err := c.fetchLayerVulnerabilitiesFromClair(ctx, digest)
	if err != nil {
		return "", []model.VulnerabilityInfo{}, fmt.Errorf("Could not fetch vulnerabilities of %s: %w", digest, err)
	}
	log.Infof("Fetched vulnerabilities of %s", digest)

	for _, feature := range rawVulnerabilities.Features {
		if len(feature.Vulnerabilities) > 0 {
			for _, vulnerability := range feature.Vulnerabilities {

				var meta metadataT
				json.Unmarshal([]byte(vulnerability.Metadata), &meta)
				if err != nil {
					log.Errorf("unmarshal raw metadata %+v,digest %s",vulnerability.Metadata,digest)
					return "", []model.VulnerabilityInfo{}, fmt.Errorf("Failed to unmarshal metadata of %s: %w", digest, err)
				}

				newVuln := model.VulnerabilityInfo{
					FeatureName:    feature.Name,
					FeatureVersion: feature.Version,
					ID:             vulnerability.Name,
					Namespace:      vulnerability.NamespaceName,
					Description:    vulnerability.Description,
					Links:          []string{vulnerability.Link},
					Severity:       vulnerability.Severity,
					FixedBy:        vulnerability.FixedBy,

					CVSS: model.CVSSVulnerabilityInfo{
						CVSSv2Vector:              meta.NVD.CVSSv2.Vectors,
						CVSSv2Score:               meta.NVD.CVSSv2.Score.String(),
						CVSSv3Vector:              meta.NVD.CVSSv3.Vectors,
						CVSSv3Score:               meta.NVD.CVSSv3.Score.String(),
						CVSSv3ImpactScore:         meta.NVD.CVSSv3.ImpactScore.String(),
						CVSSv3ExploitabilityScore: meta.NVD.CVSSv3.ExploitabilityScore.String(),
					},
				}

				for _, cnvd := range meta.CNVD {
					newVuln.CNVDs = append(newVuln.CNVDs, model.CNVDVulnerabilityInfo{
						Number:      cnvd.Number,
						Title:       cnvd.Title,
						Severity:    cnvd.Severity,
						RefLink:     cnvd.RefLink,
						Description: cnvd.Description,
					})
				}

				vulnerabilitiesMap[newVuln.ID] = newVuln
			}
		}
	}
	for _, vulnerability := range vulnerabilitiesMap {
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return rawVulnerabilities.NamespaceName, vulnerabilities, nil
}

func (c *Client) fetchLayerVulnerabilitiesFromClair(ctx context.Context, layerID string) (NewerLayer, error) {

	reqPath := fmt.Sprintf(getLayerFeaturesURI, c.clairAddr, c.clairPort, layerID)
	request, err := http.NewRequest("GET", reqPath, nil)
	if err != nil {
		return NewerLayer{}, fmt.Errorf("Failed to prepare request to Clair: %w", err)
	}

	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return NewerLayer{},fmt.Errorf("Failed to send request to Clair: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return NewerLayer{},fmt.Errorf("Failed to read response from Clair: %w", err)
		}
		return NewerLayer{}, fmt.Errorf("Expected Clair to return status 200, got: %v, body: %v", response.StatusCode, string(body))
	}

	var apiResponse NewerLayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		return NewerLayer{},fmt.Errorf("Failed to decode reponse from Clair: %w", err)
	}
	if apiResponse.Error != nil {
		return NewerLayer{}, fmt.Errorf("Clair responded with error: %v", apiResponse.Error.Message)
	}

	return apiResponse.Layer, nil
}
