FROM alpine:latest
ARG TARGETARCH
ARG TARGETVARIANT

ADD vnts_$TARGETARCH$TARGETVARIANT /usr/sbin/vnts

RUN chmod +x /usr/sbin/vnts

RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata

WORKDIR /app

ENV TZ Asia/Shanghai
ENV LANG=zh_CN

EXPOSE 29872/tcp
EXPOSE 29871/tcp

VOLUME /app

STOPSIGNAL SIGINT

ENTRYPOINT ["/usr/sbin/vnts"]
