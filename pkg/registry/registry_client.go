package registry


import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/opencontainers/go-digest"
	log "github.com/sirupsen/logrus"
	"io"
	"time"
)

const (
	RegistryClientRetryCount    = 5
	RegistryClientRetryInterval = 2 * time.Second
)

type RegistryClient struct {
	ctx 		context.Context
	username 	string
	password 	string
	repository 	string
	url 		string				//registry url
	skipRegistryTLSVerify bool
	registryClient *registry.Registry
}

func NewRegistryClient(username,password,repository,url string,skipRegistryTLSVerify bool) (*RegistryClient,error){
	rci := &RegistryClient{
		username: username,
		password: password,
		repository: repository,
		url: url,
		skipRegistryTLSVerify: skipRegistryTLSVerify,
	}
	client, err := registry.New(url, username, password)
	if err != nil && skipRegistryTLSVerify {
		// seems like error Golang's x509 package doesn't support error wrapping API yet:
		// https://github.com/golang/go/issues/30322
		//var hostnameErr *x509.HostnameError
		//if errors.As(err, &hostnameErr) { ... }
		// Therefore we must unwrap the error from HTTP package manually and try to cast

		// Check for any type of error defined in x509 package.
		_, ok1 := errors.Unwrap(err).(x509.SystemRootsError)
		_, ok2 := errors.Unwrap(err).(x509.CertificateInvalidError)
		_, ok3 := errors.Unwrap(err).(x509.UnknownAuthorityError)
		_, ok4 := errors.Unwrap(err).(x509.HostnameError)
		if ok1 || ok2 || ok3 || ok4 {
			log.Info("Certificate validation failed, but insecure option is on - will retry and skip TLS cert verification")
			client, err = registry.NewInsecure(url, username, password)
		}
	}
	if err != nil {
		log.Errorf("create new registry client err:%v",err)
		return nil,err
	}
	rci.registryClient = client
	return rci,nil
}

func (rc *RegistryClient) GetLayers(version,repository,digest string ) ([]string, error) {
	layers := make([]string, 0)
	uniqueLayers := make(map[string]bool)
	if version == "v1" {
		manifest, err := rc.registryClient.Manifest(repository, digest)
		if err != nil {
			return []string{}, fmt.Errorf("Could not read docker V1 manifest: %w", err)
		}
		for _, layer := range manifest.Manifest.FSLayers {
			layerDigest := layer.BlobSum.String()
			if _, ok := uniqueLayers[layerDigest]; ok {
				return []string{}, fmt.Errorf("Found duplicate layer digest in V1 manifest")
			}
			uniqueLayers[layerDigest] = true
			layers = append([]string{layerDigest}, layers...)
		}
	} else if version == "v2" {
		manifest, err := rc.registryClient.ManifestV2(repository, digest)
		if err != nil {
			return []string{}, fmt.Errorf("Could not read docker V2 manifest: %w", err)
		}
		for _, layer := range manifest.Manifest.Layers {
			layerDigest := layer.Digest.String()
			if _, ok := uniqueLayers[layerDigest]; ok {
				return []string{}, fmt.Errorf("Found duplicate layer digest in V2 manifest")
			}
			uniqueLayers[layerDigest] = true
			layers = append(layers, layerDigest)
		}
	}
	return layers, nil
}

func (rc *RegistryClient) DownloadBlob(repository string,digest digest.Digest) (r io.ReadCloser,err error) {
	for i:=0 ; i < RegistryClientRetryCount; i++ {
		r,err = rc.registryClient.DownloadBlob(repository,digest)
		if err == nil {
			return r,err
		}
		time.Sleep(time.Duration(RegistryClientRetryInterval) * time.Second)
	}
	return nil,err
}
func (rc *RegistryClient) GetManifestDigest(repository,tag string) (digest.Digest,error) {
	return rc.registryClient.ManifestDigest(repository,tag)
}