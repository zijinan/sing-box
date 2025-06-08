# Sing-box 一键安装脚本

这是一个基于 [JollyRoger](https://jollyroger.top/sites/436.html) 文档编写的 sing-box 一键安装脚本，支持多种代理协议的快速部署。

## 支持的协议

- **Naive**: 基于 HTTP/2 的代理协议，安全性高
- **Reality**: VLESS + Reality 协议，强抗封锁
- **Reality（偷自己）**: 使用自己的域名和证书的 Reality 配置
- **Hysteria2**: 基于 UDP 的高速代理协议

## 系统要求

- Ubuntu/Debian 系统
- Root 权限
- 开放防火墙 443 端口
- 准备一个域名（某些协议需要）

## 使用方法

### 1. 下载并运行脚本

```bash
# 下载脚本
wget https://raw.githubusercontent.com/your-repo/install_singbox.sh

# 添加执行权限
chmod +x install_singbox.sh

# 运行脚本
sudo ./install_singbox.sh
```

或一键运行：

```bash
bash <(curl -s https://raw.githubusercontent.com/your-repo/install_singbox.sh)
```

### 2. 选择协议

脚本会显示菜单，根据需要选择：

```
1. 安装 Naive 协议       - 需要域名和SSL证书
2. 安装 Reality 协议     - 需要伪装域名
3. 安装 Reality（偷自己）- 需要自己的域名和SSL证书
4. 安装 Hysteria2 协议   - 需要域名和SSL证书
5. 查看服务状态
6. 重启服务
7. 查看日志
0. 退出
```

### 3. 根据提示配置

不同协议需要不同的配置信息：

#### Naive 协议
- 用户名
- 密码
- 域名

#### Reality 协议
- 伪装域名（如：www.microsoft.com）

#### Reality（偷自己）
- 你的域名

#### Hysteria2 协议
- 密码
- 域名
- 上行带宽（可选，默认100Mbps）
- 下行带宽（可选，默认20Mbps）

## 管理命令

安装完成后，可以使用以下命令管理服务：

```bash
# 启动服务
systemctl start sing-box

# 停止服务
systemctl stop sing-box

# 重启服务
systemctl restart sing-box

# 查看状态
systemctl status sing-box

# 查看日志
journalctl -u sing-box -f

# 启用开机自启
systemctl enable sing-box

# 禁用开机自启
systemctl disable sing-box
```

## 配置文件位置

- Sing-box 配置文件：`/etc/sing-box/config.json`
- Nginx 配置文件：`/etc/nginx/nginx.conf`（Reality偷自己时使用）
- SSL 证书位置：`/etc/ssl/private/`

## 卸载方法

```bash
systemctl disable --now sing-box && rm -f /usr/local/bin/sing-box /etc/sing-box/config.json /etc/systemd/system/sing-box.service
```

## 注意事项

1. **域名解析**：确保域名已正确解析到服务器IP
2. **防火墙**：确保开放443端口
3. **SSL证书**：脚本会自动申请Let's Encrypt证书
4. **Reality协议**：伪装域名建议选择支持TLS 1.3、X25519和H2的大型网站
5. **端口冲突**：如果443端口被占用，脚本会自动停止相关服务

## 客户端配置

### Naive 客户端配置示例
```json
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://username:password@domain.com"
}
```

### Reality 客户端需要的信息
- 服务器地址
- UUID
- PublicKey
- ShortId
- ServerName（伪装域名）

### Hysteria2 客户端需要的信息
- 服务器地址:443
- 密码

## 故障排除

1. **服务启动失败**：检查配置文件语法和证书路径
2. **证书申请失败**：确保域名解析正确，80端口未被占用
3. **连接失败**：检查防火墙设置和端口开放情况

## 脚本特性

- ✅ 自动安装所有依赖
- ✅ 自动申请SSL证书
- ✅ 自动生成配置文件
- ✅ 自动启动和配置服务
- ✅ 彩色日志输出
- ✅ 错误处理和回滚
- ✅ 交互式菜单操作

## 更新日志

- v1.0: 初始版本，支持四种主要协议

## 免责声明

本脚本仅用于学习和研究目的，请遵守当地法律法规。使用本脚本所造成的任何后果由使用者自行承担。

## 参考文档

基于 [JollyRoger](https://jollyroger.top/sites/436.html) 的教程编写。 