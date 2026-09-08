# VNTS2

**vnts2** 配置文件在线生成：[https://lmq8267.github.io/vnts2](https://lmq8267.github.io/vnts2/)

### DOcker部署命令示例：

其中`/你的宿主机文件目录`是对应你宿主机的目录。

> 💡 **首次启动无需手动创建配置文件**：容器首次运行时会自动生成 `config.toml`（含完整中文注释）到你的挂载目录，同时自动生成自签名 TLS 证书 `cert.pem` / `key.pem` 固化在同一个持久化映射中（重启、重建容器均不丢失）。之后按需修改 `config.toml` 并重启容器即可生效。

- CMD

```
docker run --name vnts2 \
  -v /你的宿主机文件目录:/app \
  -p 29872:29872/tcp \
  -p 29872:29872/udp \
  -p 29871:29871/tcp \
  -p 29873:29873/udp \
  -p 500:500/udp \
  -p 4500:4500/udp \
  -p 51820:51820/udp \
  --restart=always -d lmq8267/vnts2
```

> 端口说明（后 4 个为可选功能，按需映射）：
> - `29872/tcp`+`29872/udp`：TCP / WebSocket / QUIC 客户端接入（QUIC 为 UDP，默认启用）
> - `29871/tcp`：Web 管理端
> - `29873/udp`：服务端互联（多节点集群）
> - `500/udp`、`4500/udp`：IKEv2/IPsec 接入（NAT-T 穿透）
> - `51820/udp`：WireGuard 接入

- docker-compose.yaml

```
version: "3.8"

services:
  vnts2:
    image: lmq8267/vnts2
    container_name: vnts2
    restart: always
    ports:
      - "29872:29872/tcp"
      - "29872:29872/udp"
      - "29871:29871/tcp"
      - "29873:29873/udp"    # 可选：服务端互联
      - "500:500/udp"        # 可选：IKEv2
      - "4500:4500/udp"      # 可选：IKEv2 NAT-T
      - "51820:51820/udp"    # 可选：WireGuard
    volumes:
      - /你的宿主机文件目录:/app
```


### vnts2参数

```
-c, --conf <CONF>   配置文件路径，默认 ./config.toml
      --conf-example  输出配置文件示例
```

> - 不传 `-c` 时默认读取容器工作目录 `/app/config.toml`；入口脚本会在文件缺失时自动生成默认配置。
> - `cert`/`key` 不配置时，程序首次启动将自动生成自签名 TLS 证书（`cert.pem` / `key.pem`）到工作目录，即挂载卷 `/app`，随容器持久化保存。

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

# IKEv2/IPsec 接入（可选；启用后需要管理员/root权限绑定 500/4500）
# [ikev2]
# enabled = true
# ike_bind = "0.0.0.0:500"
# natt_bind = "0.0.0.0:4500"
# server_address = "vpn.example.com" # 客户端实际连接地址
# remote_id = "vpn.example.com"
# cert = "ikev2-cert.pem"
# key = "ikev2-key.pem"
# dns = []
#
# WireGuard 接入（可选；使用独立 UDP 监听端口）
# [wireguard]
# enabled = true
# bind = "0.0.0.0:51820"
# endpoint = "vpn.example.com:51820"
# private_key = "" # 留空时首次启用自动生成
# persistent_keepalive = 25

# 自定义虚拟网段 格式：网络编号 = "网段"
[custom_nets]

# net1 = "10.25.0.0/24"
# net2 = "10.27.1.0/24"
```
