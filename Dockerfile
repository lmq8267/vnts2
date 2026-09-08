FROM alpine:latest
ARG TARGETARCH
ARG TARGETVARIANT

ADD vnts2_$TARGETARCH$TARGETVARIANT /usr/sbin/vnts2

RUN chmod +x /usr/sbin/vnts2

RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata

WORKDIR /app

ENV TZ Asia/Shanghai
ENV LANG=zh_CN

# ============ 客户端接入协议端口 ============
EXPOSE 29872/tcp      # TCP 混合监听（TCP + WebSocket 同端口自动识别）
EXPOSE 29872/udp      # QUIC 监听（与 TCP 同端口复用，基于 UDP，默认启用）
EXPOSE 29871/tcp      # Web 管理端
# ============ 可选功能端口 ============
EXPOSE 29873/udp      # 服务端互联（多节点集群专用 QUIC，可选）
EXPOSE 500/udp        # IKEv2/IPsec 接入（可选）
EXPOSE 4500/udp       # IKEv2 NAT-T 穿透（可选）
EXPOSE 51820/udp      # WireGuard 接入（可选）

VOLUME /app

# 入口脚本：首次无配置文件时自动生成默认配置，
# 自动生成的 TLS 证书固化到挂载卷 /app（cert.pem / key.pem），随映射持久保存
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

STOPSIGNAL SIGINT

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
