# VNTS2

**vnts2** 配置文件在线生成：[https://lmq8267.github.io/vnts2](https://lmq8267.github.io/vnts2/)

### DOcker部署命令示例：

其中`/你的宿主机文件目录`是对应你宿主机的目录，并且需要在这个目录里面新建一个配置文件`config.toml`,配置文件参考下方的[配置文件示例](./README.md#配置文件示例)

- CMD

```
docker run --name vnts2 -v /你的宿主机文件目录:/app -p 29872:29872/tcp -p 29871:29871/tcp --restart=always -d lmq8267/vnts2 -c /app/config.toml
```

- docker-compose.yaml

```
version: "3.8"

services:
  vnts2:
    image: lmq8267/vnts2
    container_name: vnts2
    restart: always
    command: -c /app/config.toml
    ports:
      - "29872:29872/tcp"
      - "29871:29871/tcp"
    volumes:
      - /你的宿主机文件目录:/app
```


### vnts2参数

```
-c, --conf <CONF>   配置文件路径，默认 ./config.toml
      --conf-example  输出配置文件示例
```

### 配置文件示例

```
# 绑定tcp地址，不写则不启用tcp服务
tcp_bind = "0.0.0.0:29872"
# 绑定quic地址，不写则不启用quic服务
quic_bind = "0.0.0.0:29872"
# 绑定wss地址，不写则不启用wss服务
ws_bind = "0.0.0.0:29872"
# 默认虚拟网段
network = "10.26.0.0/24"
# 网络编号白名单
white_list = []
# IP租约时长，单位秒，默认24小时，离线超过这个时间IP就会被回收
lease_duration = 86400
# Web管理端绑定地址，不写则不启用web服务
web_bind = "0.0.0.0:29871"
# 管理端登录用户名密码
username = "admin"
# 管理端登录用户密码
password = "admin"
# 是否启用数据持久化
persistence = true

# tls证书不填时将自动生成
# 自定义tls证书路径
cert = "cert.pem"
# 自定义tls私钥路径
key = "key.pem"

# 服务端互联配置（可选）
# 服务端之间通信的UDP端口，不填则不启用服务端互联
# server_quic_bind = "0.0.0.0:29873"
# 其他服务器地址列表
# peer_servers = ["server1.example.com:29873", "192.168.1.100:29873"]
# 服务器验证码，用于服务器之间的身份验证
# server_token = "your-secret-token"

# 自定义虚拟网段 格式：网络编号 = "网段"
[custom_nets]

# net1 = "10.25.0.0/24"
# net2 = "10.27.1.0/24"
```
