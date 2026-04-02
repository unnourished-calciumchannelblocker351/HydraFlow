<h1 align="center">🐉 HydraFlow</h1>

<p align="center">
  <strong>自适应多协议代理系统，具有自动审查检测和绕过功能</strong>
</p>

<p align="center">
  <a href="https://github.com/Evr1kys/HydraFlow/releases"><img src="https://img.shields.io/github/v/release/Evr1kys/HydraFlow?style=flat-square" alt="Release"></a>
  <a href="https://github.com/Evr1kys/HydraFlow/actions"><img src="https://img.shields.io/github/actions/workflow/status/Evr1kys/HydraFlow/ci.yml?style=flat-square" alt="CI"></a>
  <a href="https://github.com/Evr1kys/HydraFlow/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Evr1kys/HydraFlow?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="README.md">English</a> &bull;
  <a href="README.ru.md">Русский</a> &bull;
  <b>中文</b>
</p>

---

## 问题

政府运营的深度包检测（DPI）系统（如俄罗斯的 ТСПУ）在多个层面运作：签名分析、TLS 指纹识别、IP/ASN 关联、行为分析和主动探测。没有任何一种绕过技术能在所有运营商和网络环境下可靠运行。

用户被迫在不同协议之间手动切换，凭猜测寻找适合自己运营商的配置，并不得不忍受之前有效的方法突然被封锁后的断连。

## 解决方案

HydraFlow 是一个自适应代理系统，能够自动检测审查条件并选择最优的绕过策略。正如神话中的九头蛇 ── 砍掉一个头，长出两个新的。

```
                        ┌─────────────────────────────────┐
                        │        HydraFlow 客户端          │
                        │                                  │
                        │  ┌────────┐┌────────┐┌────────┐ │
                        │  │Reality ││ XHTTP  ││Hysteria│ │
                        │  │ (TCP)  ││ (CDN)  ││ (QUIC) │ │
                        │  └───┬────┘└───┬────┘└───┬────┘ │
                        │      │         │         │      │
                        │  ┌───▼─────────▼─────────▼───┐  │
                        │  │      协议选择器            │  │
                        │  │  ┌──────────────────────┐  │  │
                        │  │  │ 审查探测引擎         │  │  │
                        │  │  │                      │  │  │
                        │  │  └──────────────────────┘  │  │
                        │  └────────────┬───────────────┘  │
                        │               │                  │
                        │  ┌────────────▼───────────────┐  │
                        │  │  智能订阅                  │  │
                        │  │  多协议 + 优先级排序       │  │
                        │  └────────────────────────────┘  │
                        └───────────────┬──────────────────┘
                                        │
                                        ▼
                        ┌─────────────────────────────────┐
                        │        HydraFlow 服务端          │
                        │                                  │
                        │  ┌────────┐┌────────┐┌────────┐ │
                        │  │Reality ││ XHTTP  ││Hysteria│ │
                        │  │ :443   ││ CDN    ││  :UDP  │ │
                        │  └────────┘└────────┘└────────┘ │
                        │                                  │
                        │  ┌────────────────────────────┐  │
                        │  │  封锁状态聚合器            │  │
                        │  │  匿名客户端报告            │  │
                        │  └────────────────────────────┘  │
                        └─────────────────────────────────┘
```

## 功能特性

### 自适应协议选择
HydraFlow 维护一个按优先级排列的绕过方法列表，并根据实时网络状况在它们之间自动切换。

**支持的协议：**
- **VLESS + Reality** ── TLS 1.3 伪装，借用服务端证书
- **VLESS + XHTTP** ── 基于 HTTP 的传输，通过 CDN（Cloudflare、Gcore）中转
- **Hysteria2** ── 基于 QUIC 的协议，带 UDP 混淆
- **ShadowTLS v3** ── 使用真实证书的合法 TLS 握手
- **AmneziaWG** ── 具有抗 DPI 特性的改进版 WireGuard
- **链式代理** ── 通过非审查地区的中间节点路由流量

### 审查探测引擎
在建立连接之前，HydraFlow 会运行轻量级探测来判断审查环境：

```go
result := probe.Run(ctx, &probe.Config{
    Target:  "your-server.com:443",
    Tests: []probe.Test{
        probe.TLSFingerprint{},    // 检测 JA3/JA4 过滤
        probe.PortReachability{},  // 检查 TCP/UDP 端口可达性
        probe.SNIFiltering{},      // 测试基于 SNI 的封锁
        probe.FragmentBypass{},    // 寻找最佳分片大小
        probe.QUICAvailability{},  // 测试 UDP/QUIC 可用性
    },
})

protocol := selector.Best(result)
```

### 智能订阅

单个订阅链接可提供多个按优先级排序的协议配置。当封锁条件变化时，服务端会主动推送更新。

```yaml
# .hydra.yml
version: 1
server: "nl-1.example.com"

protocols:
  - name: "reality-chain"
    priority: 1
    transport: tcp
    security: reality
    chain:
      - host: "ru-relay.example.com"
        port: 443
        sni: "ya.ru"
      - host: "nl-exit.example.com"
        port: 443
        sni: "www.microsoft.com"

  - name: "xhttp-cdn"
    priority: 2
    transport: xhttp
    cdn: cloudflare
    host: "cdn.example.com"

  - name: "hysteria2"
    priority: 3
    transport: quic
    ports: [443, 8443, 10443]
    obfs: salamander

blocking_map:
  megafon:
    blocked: [reality-direct]
    recommended: [reality-chain, xhttp-cdn]
  mts:
    blocked: [reality-direct, hysteria2]
    recommended: [xhttp-cdn]
```

### 众包封锁地图

客户端匿名上报各运营商下各协议的可用状态。服务端将这些数据聚合为实时封锁地图，帮助新用户立即以最优协议完成连接。

```
运营商            Reality    XHTTP/CDN   Hysteria2   ShadowTLS
─────────────────────────────────────────────────────────────
МегаФон (美加丰)  已封锁     正常        缓慢        正常
МТС (MTS)         已封锁     正常        已封锁      正常
Билайн (Beeline)  部分封锁   正常        正常        正常
Теле2 (Tele2)     已封锁     正常        正常        正常
Ростелеком        已封锁     正常        缓慢        正常
Дом.ру            已封锁     正常        正常        部分封锁
─────────────────────────────────────────────────────────────
                          更新时间：5 分钟前
```

### 一键服务端部署

```bash
curl -fsSL https://get.hydraflow.dev | bash
```

或使用 Docker：

```bash
docker run -d --name hydraflow --network host \
  -v /etc/hydraflow:/etc/hydraflow \
  ghcr.io/evr1kys/hydraflow:latest
```

安装程序会自动完成以下步骤：
- 检测你的主机服务商并确定最优配置
- 生成密钥和证书
- 为你服务器所在 ASN 寻找最佳 Reality SNI 域名
- 配置多协议监听
- 创建订阅端点
- 启用证书自动续期

## 快速开始

### 服务端

```bash
# 安装
curl -fsSL https://get.hydraflow.dev | bash

# 交互式配置向导
hydraflow init

# 启动
systemctl start hydraflow

# 生成订阅链接
hydraflow sub --generate
# → https://your-server.com/sub/a1b2c3d4e5f6
```

### 客户端

**Android：** 从 [GitHub Releases](https://github.com/Evr1kys/HydraFlow/releases) 或 F-Droid 下载

**iOS：** 使用任意 V2Ray 兼容客户端（V2Box、Streisand、FoXray）导入 HydraFlow 订阅

**桌面端：**
```bash
# macOS
brew install hydraflow

# Linux
curl -fsSL https://get.hydraflow.dev/client | bash

# Windows
# 从 GitHub Releases 下载
```

**连接：**
```bash
hydraflow connect --sub "https://your-server.com/sub/a1b2c3d4e5f6"
```

HydraFlow 会自动探测你的网络环境，选择最佳协议并完成连接。

## 工作原理

```
1. 客户端获取订阅
   └→ 接收多协议配置 + 封锁地图

2. 探测引擎执行审查检测（约 2 秒）
   ├→ TLS 指纹：正常
   ├→ TCP:443 到服务器：已封锁（DPI 识别到 Reality）
   ├→ QUIC:443 到服务器：正常
   └→ CDN 端点：正常

3. 协议选择器挑选最优方案
   └→ 选定：xhttp-cdn（优先级 2，因为 TCP:443 被封锁）

4. 通过 Cloudflare CDN 建立连接
   └→ DPI 看到的是：发往 Cloudflare IP 的 HTTPS 流量（合法）

5. 后台监控持续关注连接质量
   └→ 若 CDN 变慢 → 自动切换到 Hysteria2
```

## 架构

```
hydraflow/
├── core/                 # 核心代理引擎
│   ├── engine.go         # 协议编排
│   ├── selector.go       # 自适应协议选择
│   ├── monitor.go        # 连接健康监控
│   └── config.go         # 配置管理
│
├── protocols/            # 协议实现
│   ├── reality/          # VLESS + Reality
│   ├── xhttp/            # 通过 CDN 的 XHTTP
│   ├── hysteria2/        # Hysteria2 (QUIC)
│   ├── shadowtls/        # ShadowTLS v3
│   └── chain/            # 多跳链式代理
│
├── discovery/            # 审查检测
│   ├── probe.go          # 网络探测引擎
│   ├── fingerprint.go    # TLS/DPI 指纹识别
│   ├── blockmap.go       # 众包封锁地图
│   └── reporter.go       # 匿名遥测上报
│
├── subscription/         # 智能订阅系统
│   ├── format.go         # .hydra.yml 解析器
│   ├── server.go         # 订阅 HTTP 端点
│   ├── updater.go        # 向客户端推送更新
│   └── compat.go         # V2Ray/Clash/sing-box 导出
│
├── server/               # 服务端组件
│   ├── installer.go      # 一键安装程序
│   ├── snifinder.go      # Reality SNI 自动发现
│   ├── certman.go        # 证书管理
│   └── multi.go          # 多协议监听器
│
├── client/               # 客户端应用
│   ├── cli/              # CLI 客户端
│   ├── android/          # Android 应用（Kotlin）
│   ├── desktop/          # 桌面 GUI（Wails/Go）
│   └── tun/              # TUN 设备管理
│
├── cmd/
│   ├── hydraflow/        # 主程序
│   ├── hf-server/        # 仅服务端程序
│   └── hf-probe/         # 独立探测工具
│
└── deploy/
    ├── docker/           # Dockerfile + compose
    ├── systemd/          # 服务单元
    └── cloud-init/       # VPS 初始化模板
```

## 文档

| 文档 | 说明 |
|------|------|
| [架构设计](docs/architecture.md) | 系统设计与组件交互 |
| [协议说明](docs/protocols.md) | 支持的协议及其配置方式 |
| [订阅格式](docs/subscription-format.md) | `.hydra.yml` 规范 |
| [服务端部署](docs/server-setup.md) | 服务端运维部署指南 |
| [客户端指南](docs/client-guide.md) | 连接使用指南 |
| [探测引擎](docs/probe-engine.md) | 审查检测的工作原理 |
| [封锁地图](docs/blocking-map.md) | 众包遥测系统 |
| [参与贡献](CONTRIBUTING.md) | 如何参与项目贡献 |
| [安全策略](SECURITY.md) | 安全策略与威胁模型 |

## 对比

| 功能 | HydraFlow | Xray | sing-box | Clash | Amnezia | Outline |
|------|-----------|------|----------|-------|---------|---------|
| 多协议支持 | 是 | 是 | 是 | 是 | 部分 | 否 |
| 自动协议选择 | **是** | 否 | 否 | 否 | 否 | 否 |
| 审查探测 | **是** | 否 | 否 | 否 | 否 | 否 |
| 众包封锁地图 | **是** | 否 | 否 | 否 | 否 | 否 |
| 智能订阅 | **是** | 否 | 部分 | 部分 | 否 | 否 |
| 一键部署 | **是** | 否 | 否 | 否 | 是 | 是 |
| 链式代理 | 是 | 是 | 是 | 是 | 否 | 否 |
| CDN 绕过（XHTTP） | 是 | 是 | 是 | 否 | 否 | 否 |
| Hysteria2（QUIC） | 是 | 是 | 是 | 是 | 否 | 否 |
| SNI 自动发现 | **是** | 否 | 否 | 否 | 否 | 否 |

## 路线图

### v0.1.0 ── 基础框架
- [ ] 核心代理引擎与协议抽象层
- [ ] VLESS + Reality 协议支持
- [ ] VLESS + XHTTP（CDN）协议支持
- [ ] 基础订阅服务端与格式定义
- [ ] Linux 和 macOS CLI 客户端
- [ ] 基于 Docker 的服务端部署

### v0.2.0 ── 智能化
- [ ] 审查探测引擎
- [ ] 自动协议选择
- [ ] Hysteria2 和 ShadowTLS 协议支持
- [ ] 链式代理配置
- [ ] 订阅推送更新

### v0.3.0 ── 社区化
- [ ] 众包封锁地图
- [ ] 匿名遥测系统
- [ ] Android 客户端应用
- [ ] 桌面 GUI 客户端
- [ ] 运营商专属配置预设

### v1.0.0 ── 正式发布
- [ ] 稳定的公共 API
- [ ] iOS 兼容的订阅导出
- [ ] 带配置向导的一键服务端安装
- [ ] Reality SNI 自动发现
- [ ] 完善的文档与多语言翻译

## 参与贡献

我们欢迎所有相信互联网自由的人参与贡献。请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

**优先方向：**
- 协议实现（尤其是新的绕过技术）
- 针对不同 DPI 系统的审查探测模块
- 客户端应用（Android、iOS、桌面端）
- 文档与翻译
- 在不同运营商和地区进行测试

## 安全

- 零日志：不记录用户流量和访问目标
- 匿名遥测：仅上报运营商名称和协议状态，不涉及 IP 地址
- 所有探测数据在客户端本地处理
- 订阅链接使用加密令牌
- 无用户追踪，不保留持久化连接元数据

详见 [SECURITY.md](SECURITY.md) 了解完整安全策略与威胁模型。

## 许可证

[MPL-2.0](LICENSE) ── 可自由使用，但对 HydraFlow 代码的修改必须保持开源。

## 致谢

HydraFlow 基于以下项目的工作成果：
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) ── Reality、XHTTP、VLESS
- [apernet/hysteria](https://github.com/apernet/hysteria) ── Hysteria2
- [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls) ── ShadowTLS
- [amnezia-vpn](https://github.com/amnezia-vpn) ── AmneziaWG
- [OONI](https://ooni.org) ── 互联网审查测量方法论
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) / [zapret](https://github.com/bol-van/zapret) ── DPI 绕过先驱

---

<p align="center">
  <em>「砍掉一个头，长出两个新的。」</em>
</p>
