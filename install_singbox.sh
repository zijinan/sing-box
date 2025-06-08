#!/bin/bash

# Sing-box 一键安装脚本
# 支持 Naive、Reality、Hysteria2 协议

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_blue() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 安装必要组件
install_dependencies() {
    log_info "正在安装必要组件..."
    apt update -y
    apt install -y curl sudo wget unzip socat cron nginx openssl net-tools
    
    # 检查安装是否成功
    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl安装失败"
        exit 1
    fi
    
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "openssl安装失败"
        exit 1
    fi
    
    log_info "依赖组件安装完成"
}

# 安装sing-box
install_singbox() {
    log_info "正在安装sing-box..."
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    
    if [[ $? -eq 0 ]]; then
        log_info "sing-box安装成功"
    else
        log_error "sing-box安装失败"
        exit 1
    fi
}

# 安装acme证书管理工具
install_acme() {
    log_info "正在安装acme证书管理工具..."
    curl https://get.acme.sh | sh
    ln -s /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
    
    # 切换CA到Let's Encrypt
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
}

# 检查网络环境
check_network_environment() {
    local has_ipv4=false
    local has_ipv6=false
    
    # 检查IPv4
    if ip -4 addr show | grep -q "inet.*global"; then
        has_ipv4=true
    fi
    
    # 检查IPv6
    if ip -6 addr show | grep -q "inet6.*global"; then
        has_ipv6=true
    fi
    
    if [[ $has_ipv4 == true && $has_ipv6 == true ]]; then
        echo "dual"
    elif [[ $has_ipv4 == true ]]; then
        echo "ipv4"
    elif [[ $has_ipv6 == true ]]; then
        echo "ipv6"
    else
        echo "none"
    fi
}

# 配置防火墙
setup_firewall() {
    log_info "正在配置防火墙..."
    
    # 检查并配置ufw
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 80/tcp >/dev/null 2>&1
        ufw allow 443/tcp >/dev/null 2>&1
        log_info "UFW防火墙规则已添加"
    fi
    
    # 检查并配置iptables
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null
    fi
    
    # 检查并配置ip6tables（IPv6环境）
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null
        ip6tables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null
        log_info "IPv6防火墙规则已添加"
    fi
}

# 申请SSL证书
apply_ssl_cert() {
    local domain=$1
    log_info "正在为域名 $domain 申请SSL证书..."
    
    # 检查网络环境
    local network_type=$(check_network_environment)
    log_info "检测到网络环境: $network_type"
    
    # 配置防火墙
    setup_firewall
    
    # 停止可能占用80端口的服务
    systemctl stop nginx 2>/dev/null
    systemctl stop sing-box 2>/dev/null
    systemctl stop apache2 2>/dev/null
    
    # 等待端口释放
    sleep 3
    
    # 清理之前可能失败的申请
    rm -rf /root/.acme.sh/${domain}_ecc/ 2>/dev/null
    
    # 根据网络环境选择申请方式
    local acme_cmd="/root/.acme.sh/acme.sh --issue -d $domain --standalone --force"
    
    case $network_type in
        "ipv6")
            log_info "使用IPv6模式申请证书..."
            $acme_cmd --listen-v6
            ;;
        "ipv4")
            log_info "使用IPv4模式申请证书..."
            $acme_cmd --listen-v4
            ;;
        "dual")
            log_info "使用双栈模式申请证书..."
            $acme_cmd
            ;;
        *)
            log_error "无法检测到有效的网络环境"
            return 1
            ;;
    esac
    
    local cert_result=$?
    
    # 如果HTTP验证失败，尝试DNS验证
    if [[ $cert_result -ne 0 ]]; then
        log_warn "HTTP验证失败，尝试使用DNS验证..."
        log_info "请手动添加DNS TXT记录，或者检查防火墙设置"
        
        # 提供手动DNS验证选项
        read -p "是否要尝试DNS验证模式？需要手动添加DNS记录 (y/n): " use_dns
        if [[ $use_dns == "y" || $use_dns == "Y" ]]; then
            log_info "启动DNS验证模式..."
            /root/.acme.sh/acme.sh --issue -d $domain --dns --force
            cert_result=$?
        fi
    fi
    
    if [[ $cert_result -eq 0 ]]; then
        # 安装证书
        mkdir -p /etc/ssl/private
        /root/.acme.sh/acme.sh --install-cert -d $domain \
            --key-file /etc/ssl/private/private.key \
            --fullchain-file /etc/ssl/private/fullchain.cer
        
        # 验证证书文件
        if [[ -f "/etc/ssl/private/fullchain.cer" && -f "/etc/ssl/private/private.key" ]]; then
            log_info "SSL证书申请和安装成功"
            return 0
        else
            log_error "证书文件安装失败"
            return 1
        fi
    else
        log_error "SSL证书申请失败"
        log_error "可能的解决方案："
        log_error "1. 检查域名是否正确解析到服务器IP"
        log_error "2. 检查防火墙是否开放80和443端口"
        log_error "3. 检查是否有其他服务占用80端口"
        
        # 提供无证书继续的选项
        read -p "是否要跳过SSL证书继续配置（不推荐，仅用于测试）？(y/n): " skip_ssl
        if [[ $skip_ssl == "y" || $skip_ssl == "Y" ]]; then
            log_warn "跳过SSL证书，使用自签名证书..."
            create_self_signed_cert $domain
            return $?
        fi
        
        return 1
    fi
}

# 创建自签名证书（备用方案）
create_self_signed_cert() {
    local domain=$1
    log_warn "创建自签名证书（仅用于测试）..."
    
    mkdir -p /etc/ssl/private
    
    # 创建自签名证书
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/private.key \
        -out /etc/ssl/private/fullchain.cer \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$domain" 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        log_warn "自签名证书创建成功（客户端需要忽略证书错误）"
        return 0
    else
        log_error "自签名证书创建失败"
        return 1
    fi
}

# 生成UUID
generate_uuid() {
    sing-box generate uuid
}

# 生成Reality密钥对
generate_reality_keypair() {
    sing-box generate reality-keypair
}

# 生成随机短ID
generate_short_id() {
    sing-box generate rand 8 --hex
}

# 配置Naive协议
configure_naive() {
    read -p "请输入用户名: " username
    read -p "请输入密码: " password
    read -p "请输入域名: " domain
    
    # 申请SSL证书
    if ! apply_ssl_cert $domain; then
        return 1
    fi
    
    # 生成配置文件
    cat > /etc/sing-box/config.json << EOF
{
    "inbounds": [
        {
            "type": "naive",
            "listen": "::",
            "listen_port": 443,
            "users": [
                {
                    "username": "$username",
                    "password": "$password"
                }
            ],
            "tls": {
                "enabled": true,
                "certificate_path": "/etc/ssl/private/fullchain.cer",
                "key_path": "/etc/ssl/private/private.key"
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct"
        }
    ]
}
EOF

    log_info "Naive配置完成"
    log_info "连接地址: https://$username:$password@$domain"
}

# 配置Reality协议
configure_reality() {
    read -p "请输入伪装域名 (例如: www.microsoft.com): " fake_domain
    
    uuid=$(generate_uuid)
    keypair=$(generate_reality_keypair)
    private_key=$(echo "$keypair" | grep "PrivateKey" | awk '{print $2}')
    public_key=$(echo "$keypair" | grep "PublicKey" | awk '{print $2}')
    short_id=$(generate_short_id)
    
    # 生成配置文件
    cat > /etc/sing-box/config.json << EOF
{
    "inbounds": [
        {
            "type": "vless",
            "listen": "::",
            "listen_port": 443,
            "users": [
                {
                    "uuid": "$uuid",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "$fake_domain",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "$fake_domain",
                        "server_port": 443
                    },
                    "private_key": "$private_key",
                    "short_id": [
                        "$short_id"
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct"
        }
    ]
}
EOF

    log_info "Reality配置完成"
    log_info "UUID: $uuid"
    log_info "PublicKey: $public_key"
    log_info "ShortId: $short_id"
    log_info "ServerName: $fake_domain"
}

# 配置Reality（偷自己）
configure_reality_steal_self() {
    read -p "请输入你的域名: " domain
    
    # 申请SSL证书
    if ! apply_ssl_cert $domain; then
        return 1
    fi
    
    uuid=$(generate_uuid)
    keypair=$(generate_reality_keypair)
    private_key=$(echo "$keypair" | grep "PrivateKey" | awk '{print $2}')
    public_key=$(echo "$keypair" | grep "PublicKey" | awk '{print $2}')
    short_id=$(generate_short_id)
    
    # 配置nginx
    cat > /etc/nginx/nginx.conf << EOF
user root;
worker_processes auto;

error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format main '[\$time_local] \$proxy_protocol_addr "\$http_referer" "\$http_user_agent"';
    access_log /var/log/nginx/access.log main;

    map \$http_upgrade \$connection_upgrade {
        default upgrade;
        ""      close;
    }

    server {
        listen 80;
        listen [::]:80;
        return 301 https://\$host\$request_uri;
    }

    server {
        listen                     127.0.0.1:8001 ssl http2;
        set_real_ip_from           127.0.0.1;
        real_ip_header             proxy_protocol;
        server_name                $domain;

        ssl_certificate            /etc/ssl/private/fullchain.cer;
        ssl_certificate_key        /etc/ssl/private/private.key;
        ssl_protocols              TLSv1.2 TLSv1.3;
        ssl_ciphers                TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers  on;

        location / {
            sub_filter                            \$proxy_host \$host;
            sub_filter_once                       off;
            set \$website                          www.lovelive-anime.jp;
            proxy_pass                            https://\$website;
            resolver                              1.1.1.1;
            proxy_set_header Host                 \$proxy_host;
            proxy_http_version                    1.1;
            proxy_ssl_server_name                 on;
            proxy_set_header Upgrade              \$http_upgrade;
            proxy_set_header Connection           \$connection_upgrade;
        }
    }
}
EOF

    # 配置sing-box
    cat > /etc/sing-box/config.json << EOF
{
    "inbounds": [
        {
            "type": "vless",
            "listen": "::",
            "listen_port": 443,
            "users": [
                {
                    "uuid": "$uuid",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "$domain",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "127.0.0.1",
                        "server_port": 8001
                    },
                    "private_key": "$private_key",
                    "short_id": [
                        "$short_id"
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct"
        }
    ]
}
EOF

    # 启动nginx
    systemctl daemon-reload
    systemctl enable nginx
    systemctl restart nginx

    log_info "Reality（偷自己）配置完成"
    log_info "域名: $domain"
    log_info "UUID: $uuid"
    log_info "PublicKey: $public_key"
    log_info "ShortId: $short_id"
}

# 配置Hysteria2协议
configure_hysteria2() {
    read -p "请输入密码: " password
    read -p "请输入域名: " domain
    read -p "请输入上行带宽(Mbps，默认100): " up_mbps
    read -p "请输入下行带宽(Mbps，默认20): " down_mbps
    
    up_mbps=${up_mbps:-100}
    down_mbps=${down_mbps:-20}
    
    # 申请SSL证书
    if ! apply_ssl_cert $domain; then
        return 1
    fi
    
    # 生成配置文件
    cat > /etc/sing-box/config.json << EOF
{
    "inbounds": [
        {
            "type": "hysteria2",
            "listen": "::",
            "listen_port": 443,
            "up_mbps": $up_mbps,
            "down_mbps": $down_mbps,
            "users": [
                {
                    "password": "$password"
                }
            ],
            "tls": {
                "enabled": true,
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/ssl/private/fullchain.cer",
                "key_path": "/etc/ssl/private/private.key"
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct"
        }
    ]
}
EOF

    log_info "Hysteria2配置完成"
    log_info "服务器: $domain:443"
    log_info "密码: $password"
}

# 启动服务
start_services() {
    log_info "正在启动sing-box服务..."
    
    # 验证配置文件
    if [[ ! -f "/etc/sing-box/config.json" ]]; then
        log_error "配置文件不存在: /etc/sing-box/config.json"
        return 1
    fi
    
    # 验证配置文件语法
    if ! sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1; then
        log_error "配置文件语法错误"
        log_error "请检查配置文件: /etc/sing-box/config.json"
        sing-box check -c /etc/sing-box/config.json
        return 1
    fi
    
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl restart sing-box
    
    sleep 3
    
    if systemctl is-active --quiet sing-box; then
        log_info "sing-box服务启动成功"
        
        # 显示服务状态
        local status=$(systemctl status sing-box --no-pager -l)
        if echo "$status" | grep -q "Active: active (running)"; then
            log_info "服务运行状态正常"
        fi
        
        # 检查端口监听
        if command -v netstat >/dev/null 2>&1; then
            log_info "检查端口监听状态:"
            netstat -tlnp | grep :443 || log_warn "未检测到443端口监听"
        fi
        
        return 0
    else
        log_error "sing-box服务启动失败"
        log_error "请检查配置文件: /etc/sing-box/config.json"
        log_error "服务状态:"
        systemctl status sing-box --no-pager
        log_error "最近日志:"
        journalctl -u sing-box --no-pager -n 20
        return 1
    fi
}

# 诊断系统
diagnose_system() {
    log_blue "=== 系统诊断 ==="
    
    # 检查网络环境
    local network_type=$(check_network_environment)
    echo "网络环境: $network_type"
    
    # 检查服务状态
    if systemctl is-active --quiet sing-box; then
        echo "Sing-box服务: 运行中"
    else
        echo "Sing-box服务: 已停止"
    fi
    
    # 检查配置文件
    if [[ -f "/etc/sing-box/config.json" ]]; then
        echo "配置文件: 存在"
        if sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1; then
            echo "配置文件语法: 正确"
        else
            echo "配置文件语法: 错误"
        fi
    else
        echo "配置文件: 不存在"
    fi
    
    # 检查证书
    if [[ -f "/etc/ssl/private/fullchain.cer" && -f "/etc/ssl/private/private.key" ]]; then
        echo "SSL证书: 存在"
        local cert_info=$(openssl x509 -in /etc/ssl/private/fullchain.cer -text -noout 2>/dev/null | grep "Not After")
        if [[ -n "$cert_info" ]]; then
            echo "证书过期时间: $cert_info"
        fi
    else
        echo "SSL证书: 不存在"
    fi
    
    # 检查端口监听
    if command -v netstat >/dev/null 2>&1; then
        echo "端口443监听状态:"
        if netstat -tlnp | grep -q ":443"; then
            netstat -tlnp | grep ":443"
        else
            echo "端口443未监听"
        fi
    fi
    
    # 检查防火墙
    if command -v ufw >/dev/null 2>&1; then
        echo "UFW状态: $(ufw status | head -1)"
    fi
    
    echo ""
}

# 显示管理命令
show_management_commands() {
    echo ""
    log_blue "=== Sing-box 管理命令 ==="
    echo "启动服务: systemctl start sing-box"
    echo "停止服务: systemctl stop sing-box"
    echo "重启服务: systemctl restart sing-box"
    echo "查看状态: systemctl status sing-box"
    echo "查看日志: journalctl -u sing-box -f"
    echo "检查配置: sing-box check -c /etc/sing-box/config.json"
    echo "配置文件: /etc/sing-box/config.json"
    echo ""
    log_blue "=== 证书管理 ==="
    echo "续期证书: /root/.acme.sh/acme.sh --cron"
    echo "查看证书: openssl x509 -in /etc/ssl/private/fullchain.cer -text -noout"
    echo ""
    log_blue "=== 卸载命令 ==="
    echo "systemctl disable --now sing-box && rm -f /usr/local/bin/sing-box /etc/sing-box/config.json /etc/systemd/system/sing-box.service"
}

# 主菜单
show_menu() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
 ____  _                   ____
/ ___|(_)_ __   __ _      | __ )  _____  __
\___ \| | '_ \ / _` |_____|  _ \ / _ \ \/ /
 ___) | | | | | (_| |_____| |_) | (_) >  <
|____/|_|_| |_|\__, |     |____/ \___/_/\_\
               |___/
EOF
    echo -e "${NC}"
    echo -e "${GREEN}Sing-box 一键安装脚本${NC}"
    echo -e "${GREEN}========================${NC}"
    echo "1. 安装 Naive 协议"
    echo "2. 安装 Reality 协议"
    echo "3. 安装 Reality（偷自己）协议"
    echo "4. 安装 Hysteria2 协议"
    echo "5. 查看服务状态"
    echo "6. 重启服务"
    echo "7. 查看日志"
    echo "8. 系统诊断"
    echo "9. 重新申请证书"
    echo "0. 退出"
    echo ""
}

# 主函数
main() {
    check_root
    
    while true; do
        show_menu
        read -p "请选择操作 [0-9]: " choice
        
        case $choice in
            1)
                log_info "开始安装 Naive 协议..."
                install_dependencies
                install_singbox
                install_acme
                configure_naive
                start_services
                show_management_commands
                ;;
            2)
                log_info "开始安装 Reality 协议..."
                install_dependencies
                install_singbox
                configure_reality
                start_services
                show_management_commands
                ;;
            3)
                log_info "开始安装 Reality（偷自己）协议..."
                install_dependencies
                install_singbox
                install_acme
                configure_reality_steal_self
                start_services
                show_management_commands
                ;;
            4)
                log_info "开始安装 Hysteria2 协议..."
                install_dependencies
                install_singbox
                install_acme
                configure_hysteria2
                start_services
                show_management_commands
                ;;
            5)
                systemctl status sing-box
                ;;
            6)
                systemctl restart sing-box
                log_info "服务已重启"
                ;;
            7)
                journalctl -u sing-box -f
                ;;
            8)
                diagnose_system
                ;;
            9)
                read -p "请输入域名: " domain
                if [[ -n "$domain" ]]; then
                    apply_ssl_cert $domain
                else
                    log_error "域名不能为空"
                fi
                ;;
            0)
                log_info "感谢使用，再见！"
                exit 0
                ;;
            *)
                log_error "无效选择，请重新输入"
                ;;
        esac
        
        if [[ $choice != 5 && $choice != 6 && $choice != 7 && $choice != 8 && $choice != 9 ]]; then
            read -p "按回车键继续..."
        fi
    done
}

# 运行主函数
main "$@" 