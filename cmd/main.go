package main

import (
	"context"
	"flag"
	log "github.com/sirupsen/logrus"
	"github.com/wadeling/clair-client/pkg/fileserver"
	"github.com/wadeling/clair-client/util"
	"os"
	"sync"
	"time"
)

func main()  {
	// Parse command-line arguments
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagClairIp:= flag.String("clair-ip", "", "Clair server ip.")
	flagClairPort := flag.Int("clair-port", 0, "Clair server port.")
	flagUser := flag.String("user", "", "registry user name.")
	flagPassword := flag.String("password", "", "registry user password.")
	flagRegistryUrl := flag.String("url", "", "registry url.")
	flagRepository := flag.String("repo", "", "repository,like: library.")
	flagImageName := flag.String("image", "", "image name,like: busybox.")
	flagTagName := flag.String("tag", "", "tag name,like: latest.")
	//flagAction := flag.String("action", "", "action: [post|get]")
	flag.Parse()

	cc := &ClairClient{
		clairServerIP: *flagClairIp,
		clairServerPort: *flagClairPort,
		username: *flagUser,
		password: *flagPassword,
		registryUrl: *flagRegistryUrl,
		repository: *flagRepository,
		imageName: *flagImageName,
		tagName: *flagTagName,
		//action: *flagAction,
		layers: make([]string,0),
		sta:make(map[string]int),
	}

	//create file server
	ctx := context.Background()
	fsIp,err := util.GetLocalIp()
	if err != nil {
		log.Error("get local ip err")
		return
	}
	fsPort := 5566
	fs,err := fileserver.NewFileServer(ctx,fileserver.FileServerRootDir,fsIp,fsIp,fsPort)
	if err != nil {
		log.Error("new file server err")
		return
	}
	cc.fs = fs

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fs.Run(ctx)
	}()

	time.Sleep(time.Duration(2)*time.Second)

	//create clair client
	cc.NewClient()

	cc.PostScanTaskToClair()

	cc.OutputVulnSta()

	wg.Wait()

	time.Sleep(time.Duration(20)*time.Second)
	log.Info("end")
}