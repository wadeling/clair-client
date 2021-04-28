package main

import (
	"flag"
	"os"
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
	}

	cc.PostScanTaskToClair()
}