# clair-client

## 背景
为了对比trivy和clair，所以写了这个client，来获取clair返回的漏洞信息。

## 环境

- macos，自建harbor，使用docker-compose 来部署 clair和postgres.
- clair的要求：clair api要求填写每层tar包所在的路径。（我没找到harbor的存储url,所以采取从harbor拉取文件，然后保存到本地文件服务器的办法)
- client逻辑：先启动一个文件服务器，然后去harbor取manifest，再根据得到的信息获取每个layer内容，作为一个tar包存到文件服务器里。
- clair要求可以访问client的文件服务。所以这里启动文件服务时要绑定local ip，不能是0.0.0.0，不然clair在容器里面访问0.0.0.0是访问不到的。

## 使用

- ./build_for_mac.sh 编译client（linux使用./build_for_linux.sh)
- ./start.sh, 镜像的漏洞结果在本地的scan_result.txt

## 统计每个软件包的漏洞

执行shell命令：
```aidl
cat scan_result.txt| jq '.[]|.featurename + " " + .id' | awk -F '"' '{print $2}'
```