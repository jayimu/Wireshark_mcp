# Wireshark MCP

Wireshark MCP 是一个基于 Model Context Protocol (MCP) 的服务器，允许 AI 助手通过 tshark 命令行工具与 Wireshark 进行交互。它将 Wireshark/tshark 的强大功能与大语言模型(LLM)的智能分析能力相结合。通过 Model Context Protocol (MCP)，该工具能够让 AI 助手直接与 tshark 进行交互，实现智能化的网络数据分析。

## 功能特性

### 基础功能
- AI 驱动分析：突出自然语言交互、智能异常检测等特性
- 交互方式：详细说明对话式分析、智能过滤和结果解读功能
- LLM 增强功能：描述了协议分析、安全分析、性能诊断和统计分析等增强功能

### 安全与验证功能
- **文件路径验证**：自动验证文件路径的有效性和安全性，防止路径遍历攻击
- **数据包数量限制**：自动验证和限制 `max_packets` 参数，最大值为 10000，防止过大的值导致系统问题
- **过滤器表达式验证**：对 Wireshark 过滤器表达式进行基本安全性检查，防止命令注入
- **错误处理优化**：改进错误处理机制，在接口列表和协议列表获取失败时返回空列表，而不是抛出异常

## 系统要求

- Python 3.9 +
- Wireshark/tshark
- MCP SDK

## 安装

1. 确保已安装 Wireshark 和 tshark:
2. 安装 Python 依赖:
```bash
pip install -r requirements.txt
```
## 使用方法

1. 启动 MCP 服务器:
```bash
python wireshark_mcp.py 
```

2. 访问状态页面查看服务状态和工具说明:
```
http://127.0.0.1:3000/status
```

3. 配置客户端 MCP 服务器:

![MCP配置示例](docs/images/286191745081560_.pic.jpg)

配置说明：
- 名称：wireshark
- 类型：服务器发送事件 (sse)
- URL：http://127.0.0.1:3000/sse

## 使用效果
![使用效果](docs/images/286201745081603_.pic.jpg)
![使用效果](docs/images/286211745081627_.pic.jpg)

## 参数说明

### max_packets（数据包数量限制）

`max_packets` 参数用于限制处理的数据包数量，默认最大值为 **10000** 个数据包（可通过 `max_packets` 参数调整，超过 10000 会自动限制）。

#### max_packets 与 AI Tokens 的关系

- **max_packets**：限制网络数据包的数量（在网络抓包分析阶段控制）
- **AI Tokens**：AI 模型处理的文本单位数量（在 AI 模型处理阶段消耗）

**数据流转关系链：**
```
网络数据包 → tshark 处理 → JSON 输出 → AI 处理 → AI 响应
   ↑              ↑              ↑           ↑
max_packets   限制这里      影响大小    消耗 tokens
```

**实际影响示例：**
- **100 个数据包**：约 500 KB JSON → 约 1,000-2,000 tokens（输入）→ 成本较低，响应快速
- **1000 个数据包**：约 5 MB JSON → 约 10,000-20,000 tokens（输入）→ 平衡 tokens 和详细程度
- **10000 个数据包**：约 50 MB JSON → 约 100,000-200,000 tokens（输入）→ 成本较高，响应较慢

**最佳实践建议：**
- 快速分析：`max_packets = 100`（消耗较少 tokens，快速响应）
- 详细分析：`max_packets = 1000`（平衡 tokens 和详细程度）
- 深度分析：`max_packets = 5000-10000`（消耗大量 tokens，但信息更全面，需谨慎使用）
- **优先使用过滤器（filter）来减少数据包数量**，而不是返回所有数据包

#### 处理 Token 限制问题的优化建议

如果遇到 "number of input tokens has exceeded max_seq_len limit" 错误，说明输出数据过大。以下是优化建议：

**1. 使用过滤器减少数据包数量（最有效）**
```python
# 只分析特定 IP 的流量
analyze_pcap(file_path, filter="ip.addr == 192.168.1.1", max_packets=5000)

# 只分析 HTTP 流量
analyze_pcap(file_path, filter="http", max_packets=3000)

# 只分析特定端口
analyze_pcap(file_path, filter="tcp.port == 80 || tcp.port == 443", max_packets=2000)
```

**2. 使用统计功能代替详细分析**
```python
# 获取统计信息而不是详细数据包（token 消耗 < 5000）
get_packet_statistics(file_path)
get_advanced_statistics(file_path, stat_type="http")
```

**3. 分批次分析**
```python
# 分析前 2000 个数据包
analyze_pcap(file_path, max_packets=2000)

# 分析特定时间范围
analyze_pcap(file_path, filter='frame.time >= "2024-01-01 10:00:00"', max_packets=2000)
```

**4. 降低 max_packets 值**
- 对于 262144 token 限制：建议 `max_packets = 1000-2000`
- 对于 131072 token 限制：建议 `max_packets = 500-1000`
- 对于 32768 token 限制：建议 `max_packets = 100-200`

**5. 使用错误分析功能（只返回异常数据包）**
```python
# 只分析错误和异常，大幅减少输出
analyze_errors(file_path, error_type="all", max_packets=5000)
```

**详细优化指南：** 请参考 [OPTIMIZATION_GUIDE.md](OPTIMIZATION_GUIDE.md)

## 更新

### Bug 修复



## 特别感谢
https://mp.weixin.qq.com/s/G_6efZFEgGTeOcRtyaNS1g?poc_token=HKpP_2ejJpvhJJ4EJ9J-8b9U5eZ3U0Jvkk_YPKoO
https://github.com/shubham-s-pandey/WiresharkMCP
