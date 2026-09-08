#!/bin/sh
# vnts2 入口脚本
# 功能：
#   1. 首次启动且无配置文件时，自动生成带完整中文注释的默认配置（config.toml）
#   2. 默认配置中注释掉 cert/key，交由 vnts2 首次启动自动生成自签名 TLS 证书，
#      证书会写入工作目录（挂载卷 /app），随持久化映射保存，容器重建后不丢失
#   3. 兼容命令行 -c/--conf 指定的配置路径，也支持 CONF_FILE 环境变量覆盖
set -e

# 默认配置文件路径，可用 CONF_FILE 环境变量覆盖
CONF_FILE="${CONF_FILE:-/app/config.toml}"

# 若命令行已通过 -c/--conf 显式指定配置，则优先使用命令行指定路径
prev=""
for arg in "$@"; do
  case "$prev" in
    -c | --conf) CONF_FILE="$arg" ;;
  esac
  case "$arg" in
    -c | --conf) prev="$arg" ;;                      # 记录参数，供下一轮取值
    --conf=*)    CONF_FILE="${arg#*=}" ;;            # 支持 --conf=path 形式
    *)           prev="" ;;
  esac
done

# 首次启动且配置文件不存在：自动生成默认配置
if [ ! -f "$CONF_FILE" ]; then
  # 确保配置所在目录存在（如 /app 挂载了空目录）
  mkdir -p "$(dirname "$CONF_FILE")"
  # 用程序自带的示例输出生成带完整注释的默认配置
  /usr/sbin/vnts2 --conf-example > "$CONF_FILE"
  # 注释掉示例中的 cert/key 示例行：让 vnts2 启动时自动生成自签名证书到工作目录
  # （挂载卷 /app），固化保存；而不是要求用户预先放置证书文件
  sed -i -e 's/^cert =/# cert =/' -e 's/^key =/# key =/' "$CONF_FILE"
  echo "[vnts2] 首次启动：未检测到配置文件，已自动生成默认配置：${CONF_FILE}"
  echo "[vnts2] 请按需修改（默认账号 admin/admin、默认虚拟网段 10.26.0.0/24）后重启容器生效。"
fi

exec /usr/sbin/vnts2 "$@"