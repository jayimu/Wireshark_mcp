# Wireshark MCP Token 优化工作流程

## 推荐工作流程

当遇到 "number of input tokens has exceeded max_seq_len limit" 错误时，建议按照以下工作流程进行分析，这样可以大幅减少 token 消耗，同时保持分析能力。

## 提问案例

### 案例 1：分析网络流量异常

**问题：** "分析这个 pcap 文件，找出异常的网络活动"

**工作流程：**
```
步骤 1: 获取统计概览
提问: "请使用 get_packet_statistics 分析 file.pcap，给我一个流量概览"

步骤 2: 根据统计结果确定关键点
AI 分析统计结果，识别：
- 流量最大的 IP: 192.168.1.100
- 异常端口: 4444
- 大量 DNS 查询

步骤 3: 分析特定流量
提问: "请使用 analyze_pcap 分析 file.pcap，过滤条件为 ip.addr == 192.168.1.100，max_packets=2000"

步骤 4: 深入分析异常端口
提问: "请分析 file.pcap 中端口 4444 的流量，max_packets=1000"
```

### 案例 2：分析 HTTP 流量

**问题：** "分析这个文件中的 HTTP 流量，找出可疑请求"

**工作流程：**
```
步骤 1: 获取 HTTP 统计
提问: "请使用 get_advanced_statistics 分析 file.pcap，统计类型为 http"

步骤 2: 根据统计结果确定关键点
AI 分析 HTTP 统计，识别：
- 异常状态码: 404, 500
- 可疑 URI: /admin/login.php
- 异常 User-Agent

步骤 3: 分析特定 HTTP 流量
提问: "请使用 analyze_pcap 分析 file.pcap，过滤条件为 http，max_packets=2000"

步骤 4: 深入分析异常请求
提问: "请分析 file.pcap 中状态码为 404 的 HTTP 请求，max_packets=1000"
```

### 案例 3：分析特定 IP 的完整通信

**问题：** "分析 192.168.1.50 的所有网络通信"

**工作流程：**
```
步骤 1: 获取该 IP 的统计信息
提问: "请使用 get_packet_statistics 分析 file.pcap，过滤条件为 ip.addr == 192.168.1.50"

步骤 2: 根据统计结果确定协议
AI 分析统计结果，识别：
- 主要协议: TCP (80, 443, 22)
- 通信对端: 多个外部 IP
- 数据量: 上传 > 下载

步骤 3: 分协议分析
提问: "请使用 analyze_pcap 分析 file.pcap，过滤条件为 ip.addr == 192.168.1.50 && tcp.port == 443，max_packets=2000"

步骤 4: 分析其他协议
提问: "请分析 file.pcap 中 192.168.1.50 的 SSH 流量（端口 22），max_packets=1000"
```

### 案例 4：分析 DNS 查询异常

**问题：** "找出异常的 DNS 查询"

**工作流程：**
```
步骤 1: 获取 DNS 统计
提问: "请使用 get_advanced_statistics 分析 file.pcap，统计类型为 dns"

步骤 2: 根据统计结果确定可疑域名
AI 分析 DNS 统计，识别：
- 异常域名: suspicious-domain.com
- 大量 NXDOMAIN 响应
- 异常查询频率

步骤 3: 分析特定 DNS 查询
提问: "请使用 analyze_pcap 分析 file.pcap，过滤条件为 dns，max_packets=2000"

步骤 4: 深入分析可疑域名
提问: "请分析 file.pcap 中包含 suspicious-domain.com 的 DNS 查询，max_packets=500"
```

### 案例 5：分析时间范围内的流量

**问题：** "分析 2024-01-01 10:00 到 11:00 之间的网络流量"

**工作流程：**
```
步骤 1: 获取该时间段的统计
提问: "请使用 get_packet_statistics 分析 file.pcap，过滤条件为 frame.time >= '2024-01-01 10:00:00' && frame.time <= '2024-01-01 11:00:00'"

步骤 2: 根据统计结果确定关键点
AI 分析统计结果，识别：
- 该时间段的主要活动
- 异常流量模式
- 关键通信

步骤 3: 分析特定时间段
提问: "请使用 analyze_pcap 分析 file.pcap，过滤条件为 frame.time >= '2024-01-01 10:00:00' && frame.time <= '2024-01-01 11:00:00'，max_packets=2000"

步骤 4: 如果需要，进一步细分时间段
提问: "请分析 file.pcap 中 10:30 到 10:45 之间的流量，max_packets=1000"
```

### 案例 6：分析错误和异常

**问题：** "找出网络中的错误和异常情况"

**工作流程：**
```
步骤 1: 使用错误分析功能（最有效）
提问: "请使用 analyze_errors 分析 file.pcap，错误类型为 all，max_packets=5000"

步骤 2: 根据错误结果确定关键问题
AI 分析错误结果，识别：
- TCP 重传
- 格式错误的数据包
- 连接问题

步骤 3: 针对特定错误类型深入分析
提问: "请使用 analyze_errors 分析 file.pcap，错误类型为 tcp，max_packets=2000"

步骤 4: 分析相关数据包
提问: "请分析 file.pcap 中发生 TCP 重传的 IP 地址的完整通信，max_packets=2000"
```