#!/bin/bash
set -e

# 使用方式: ROOT_PW=xxx bash install.sh
if [ -z "$ROOT_PW" ]; then
  echo "请设置 ROOT_PW 环境变量: ROOT_PW=你的root密码 bash install.sh"
  exit 1
fi

USER_NAME="${USER_NAME:-chuenyu}"
SINGBOX_VER="${SINGBOX_VER:-1.13.12}"
SINGBOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/sing-box-${SINGBOX_VER}-linux-amd64.tar.gz"

SU="echo $ROOT_PW | su -c"

echo "=== 一键部署 sbtool-server + singbox 透明代理 ==="
echo "用户: $USER_NAME, singbox: $SINGBOX_VER"

# 1. 安装系统依赖
echo "[1/8] 安装系统依赖..."
$SU 'apt update -qq'
$SU 'apt install -y python3 python3-pip python3-venv git curl sudo nftables'

# 2. 配置免密 sudo
echo "[2/8] 配置免密 sudo..."
$SU "usermod -aG sudo $USER_NAME"
$SU "bash -c 'echo \"$USER_NAME ALL=(ALL) NOPASSWD: ALL\" > /etc/sudoers.d/$USER_NAME'"

# 3. 下载安装 singbox（直连，失败则走代理）
echo "[3/8] 下载 singbox ${SINGBOX_VER}..."
curl -sL --connect-timeout 120 -o /tmp/sing-box.tar.gz "$SINGBOX_URL" || \
  curl -x http://192.168.50.101:8888 -sL --connect-timeout 120 -o /tmp/sing-box.tar.gz "$SINGBOX_URL"
$SU 'mkdir -p /root/singbox'
cd /tmp && tar -xzf sing-box.tar.gz
cp /tmp/sing-box-${SINGBOX_VER}-linux-amd64/sing-box /tmp/singbox_bin
$SU 'cp /tmp/singbox_bin /usr/local/bin/singbox'
$SU 'chmod +x /usr/local/bin/singbox'

# 4. 创建 singbox systemd 服务
echo "[4/8] 创建 singbox 服务..."
$SU 'tee /etc/systemd/system/singbox.service > /dev/null << EOF
[Unit]
Description=Singbox Default Server Service
Documentation=https://github.com/SagerNet/sing-box
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/singbox
ExecStart=/usr/local/bin/singbox run -D /root/singbox/
Restart=always
RestartSec=10
LimitNOFILE=1048576
Environment=ENABLE_DEPRECATED_LEGACY_DNS_FAKEIP_OPTIONS=true
Environment=ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true
Environment=ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true
Environment=ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true

[Install]
WantedBy=multi-user.target
EOF'

# 5. 配置 nftables 透明代理
echo "[5/8] 配置 nftables 透明代理..."
NET_IF=$(ip route get 1 | awk '{print $5; exit}')
$SU "tee /etc/nftables.conf > /dev/null << EOF
#!/usr/sbin/nft -f

flush ruleset

table inet singbox {
  set local_ipv4 {
    type ipv4_addr
    flags interval
    elements = {
      10.0.0.0/8,
      127.0.0.0/8,
      169.254.0.0/16,
      172.16.0.0/12,
      192.168.0.0/16,
      240.0.0.0/4
    }
  }

  set local_ipv6 {
    type ipv6_addr
    flags interval
    elements = {
      ::ffff:0.0.0.0/96,
      64:ff9b::/96,
      100::/64,
      2001::/32,
      2001:10::/28,
      2001:20::/28,
      2001:db8::/32,
      2002::/16,
      fc00::/7,
      fe80::/10
    }
  }

  chain singbox-tproxy {
    fib daddr type { unspec, local, anycast, multicast } return
    ip daddr @local_ipv4 return
    ip6 daddr @local_ipv6 return
    udp dport { 123 } return
    meta l4proto { tcp, udp } meta mark set 1 tproxy to :9888 accept
  }

  chain singbox-mark {
    fib daddr type { unspec, local, anycast, multicast } return
    ip daddr @local_ipv4 return
    ip6 daddr @local_ipv6 return
    udp dport { 123 } return
    udp dport { 53 } return
    meta mark set 1
  }

  chain mangle-output {
    type route hook output priority mangle; policy accept;
    meta l4proto { tcp, udp } skgid != 1 ct direction original goto singbox-mark
  }

  chain mangle-prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname { lo, ${NET_IF} } meta l4proto { tcp, udp } ct direction original goto singbox-tproxy
  }
}
EOF"
$SU 'systemctl enable nftables && nft -f /etc/nftables.conf'

# 6. 克隆 sbtool-server
echo "[6/8] 克隆 sbtool-server..."
cd /home/$USER_NAME
rm -rf sbtool-server
git clone https://github.com/chuenyu70/sbtool.git sbtool-server

# 7. 安装 Python 依赖
echo "[7/8] 安装 Python 依赖..."
cd /home/$USER_NAME/sbtool-server
pip3 install -r requirements.txt --break-system-packages

# 8. 创建 sbtool-server 服务并启动
echo "[8/8] 启动 sbtool-server..."
LOCAL_IP=$(hostname -I | awk '{print $1}')
$SU "tee /etc/systemd/system/sbtool-server.service > /dev/null << EOF
[Unit]
Description=sbtool-server
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=/home/$USER_NAME/sbtool-server
ExecStart=/usr/bin/python3 /home/$USER_NAME/sbtool-server/main.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF"
$SU 'systemctl daemon-reload && systemctl enable sbtool-server && systemctl restart sbtool-server'

echo ""
echo "=== 安装完成 ==="
echo "sbtool-server: http://$LOCAL_IP:8080"
echo "singbox 透明代理: tproxy 9888, mixed 2080"
$SU 'systemctl status sbtool-server --no-pager | head -8'
