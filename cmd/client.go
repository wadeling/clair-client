package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/wadeling/clair-client/pkg/registry"
)

type ClairClient struct {
	clairServerIP 		string
	clairServerPort 	int
	username string
	password string
	registryUrl string
	repository string
	imageName string
	tagName string
	fullRepoName string
	registryClient *registry.RegistryClient
}

func (cc *ClairClient) NewRegistryClient() error {
	f := fmt.Sprintf("%s/%s",cc.repository,cc.imageName)
	cc.fullRepoName = f
	client, err := registry.NewRegistryClient(cc.username,cc.password,cc.fullRepoName,cc.registryUrl,true)
	if err != nil {
		return err
	}

	cc.registryClient = client
	return nil
}
func (cc *ClairClient) PostScanTaskToClair() error {
	//create new registry client
	if cc.registryClient == nil {
		err := cc.NewRegistryClient()
		if err != nil {
			return err
		}
	}

	//get image digest
	digest, err := cc.registryClient.GetManifestDigest(cc.fullRepoName,cc.tagName)
	if err != nil {
		return err
	}
	log.Info("get image digest %s",digest.String())

	//get manifest
	layers,err := cc.registryClient.GetLayers("v2",cc.fullRepoName,digest.String())
	if err != nil {
		return err
	}
	log.Info("get layers %+v",layers)

	return nil
}

func (cc *ClairClient) GetImageVuln() error {

	return nil
}
