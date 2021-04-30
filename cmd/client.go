package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/opencontainers/go-digest"
	log "github.com/sirupsen/logrus"
	"github.com/wadeling/clair-client/pkg/clair"
	"github.com/wadeling/clair-client/pkg/fileserver"
	_ "github.com/wadeling/clair-client/pkg/model"
	"github.com/wadeling/clair-client/pkg/registry-wrap"
	"io/ioutil"
	"sort"
	"time"
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
	registryClient *registryWrap.RegistryClient
	action string

	imageDigest digest.Digest
	layers []string
	client *clair.Client

	//statistics
	sta map[string]int		// vuln servirity->num

	fs *fileserver.FileServer
}

func (cc *ClairClient) NewRegistryClient() error {
	f := fmt.Sprintf("%s/%s",cc.repository,cc.imageName)
	cc.fullRepoName = f
	client, err := registryWrap.NewRegistryClient(cc.username,cc.password,cc.fullRepoName,cc.registryUrl,true)
	if err != nil {
		return err
	}

	cc.registryClient = client
	return nil
}

func (cc *ClairClient) NewClient() error {
	ctx,_ := context.WithTimeout(context.Background(),time.Duration(10)*time.Minute)
	cc.client = &clair.Client{
		Ctx: ctx,
		ClairAddr: cc.clairServerIP,
		ClairPort: cc.clairServerPort,
	}
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
	dg, err := cc.registryClient.GetManifestDigest(cc.fullRepoName,cc.tagName)
	cc.imageDigest = dg
	if err != nil {
		return err
	}
	log.Infof("get image digest %s",dg.String())

	//get layers
	layers,err := cc.registryClient.GetLayers("v2",cc.fullRepoName,dg.String())
	if err != nil {
		return err
	}
	cc.layers = layers
	log.Infof("get layers %+v",layers)

	//download all layers before fetch vulns,cause need to take a performance for clair
	for _,layer := range layers {
		//download blob
		r,err := cc.registryClient.DownloadBlob(cc.fullRepoName,digest.Digest(layer) )
		if err != nil {
			log.Errorf("download layer %s err %v",layer,err)
			return err
		}

		// save to file server
		fp,err := cc.fs.SaveFile(layer,r)
		if err != nil {
			log.Errorf("save file err.%v",err)
			return err
		}
		log.Infof("save file to server ok,file path %s",fp)
	}

	//fetch vulnerabilities
	startTime := time.Now().Unix()
	log.Infof("start get vulnerabilities,time %v",startTime)
	var preLayerDigest string
	for i,layer := range layers {

		layerHttpPath := fmt.Sprintf("http://%s:%d/%s/%s",cc.fs.ExternalIp,cc.fs.Port,layer,fileserver.LayerFileName)
		log.Infof("layer http path:%s",layerHttpPath)

		//post to clair
		if i == 0 {
			err := cc.client.ScheduleLayerScanInClair(cc.client.Ctx,layerHttpPath,layer,"")
			if err != nil {
				log.Errorf("post layer (%d) %s to clair err %v",i,layer,err)
			} else {
				log.Infof("post layer (%d) %s to clair ok",i,layer)
			}
		} else {
			//pre layer is parent layer
			err := cc.client.ScheduleLayerScanInClair(cc.client.Ctx,layerHttpPath,layer,preLayerDigest)
			if err != nil {
				log.Errorf("post layer (%d) %s (parent:%s) to clair err %v",i,layer,preLayerDigest,err)
			} else {
				log.Infof("post layer (%d) %s to clair ok",i,layer)
			}
		}
		preLayerDigest = layer
	}

	//get scan result
	// only get last(top) layer result which contain all layer's vulnerabilities
	_, vulnerabilities, err := cc.client.GetTransformedLayerScanResultFromClair(cc.client.Ctx, preLayerDigest)
	if err != nil {
		log.Errorf("get layer %s vuln err %v",preLayerDigest,err)
		return err
	}

	endTime:= time.Now().Unix()
	log.Infof("end get vulnerabilities,time %v",endTime)

	// add to sta
	vulnName := make(map[string]int)
	for _,v := range vulnerabilities {
		s := v.Severity
		n := v.ID
		if _,ok := vulnName[n]; !ok {
			vulnName[n] = 0
		}

		if _,ok := cc.sta[s]; !ok {
			cc.sta[s] = 1
		} else {
			cc.sta[s] = cc.sta[s] + 1
		}
	}

	//write vuln detail to file
	result,err := json.Marshal(vulnerabilities)
	if err != nil {
		log.Errorf("json marshal vul err %v",err)
	} else {
		err = ioutil.WriteFile("scan_result.txt", result, 0644)
		if err != nil {
			log.Errorf("write result err %v",err)
		}
	}

	//sort vuln name
	keys := make([]string,0)
	for k,_ := range vulnName {
		keys = append(keys,k)
	}
	sort.Strings(keys)

	//write vuln name to file which will be used to diff with trivy
	vulnStr := ""
	for _,v := range keys {
		vulnStr = vulnStr + v + "\n"
	}
	err = ioutil.WriteFile("scan_vuln_name.txt",([]byte)(vulnStr), 0644)
	if err != nil {
		log.Errorf("write vuln name err %v",err)
	}

	log.Info("post layer to clair end")

	return nil
}

func (cc *ClairClient) GetImageVuln() error {

	return nil
}

func (cc *ClairClient) OutputVulnSta() error {
	total := 0
	for k,v := range cc.sta {
		total = total + v
		log.Infof("severity %s num %d",k,v)
	}
	log.Infof("total vulnerabilities num %d",total)
	return nil
}
