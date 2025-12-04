# Wireshark MCP

Wireshark MCP 是一个基于 Model Context Protocol (MCP) 的服务器，允许 AI 助手通过 tshark 命令行工具与 Wireshark 进行交互。它将 Wireshark/tshark 的强大功能与大语言模型(LLM)的智能分析能力相结合，实现智能化的网络数据分析。

## 功能特性

### 基础功能
- AI 驱动分析：突出自然语言交互、智能异常检测等特性
- 交互方式：详细说明对话式分析、智能过滤和结果解读功能
- LLM 增强功能：描述了协议分析、安全分析、性能诊断和统计分析等增强功能

## 系统要求

- Python 3.9+
- Wireshark/tshark（已安装且在 PATH 中可用）
- MCP SDK

## 安装

1. 确保已安装 Wireshark 和 tshark  
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
```text
http://127.0.0.1:3000/status
```

3. 配置客户端 MCP 服务器:

![MCP配置示例](docs/images/286191745081560_.pic.jpg)

配置说明：
- 名称：wireshark
- 类型：服务器发送事件 (sse)
- URL：`http://127.0.0.1:3000/`

## 使用效果
![使用效果](docs/images/286201745081603_.pic.jpg)
![使用效果](docs/images/286211745081627_.pic.jpg)

## LLM 使用说明与 tokens 控制

由于大模型有 **上下文长度限制**（例如 128k tokens），如果一次性把大量 tshark JSON 输出喂给模型，很容易导致：

### 默认分析策略（给大模型看的提示词）

你可以将下面的内容配置到 MCP 的 `instructions` 或上游大模型的系统提示中：

```text
你是一个专门做网络流量分析的助手，通过 Wireshark MCP 工具来分析 pcap/pcapng 文件和实时抓包数据。
用户不会记工具名和参数，只会用自然语言提问；你需要自己选择和组合合适的工具，并严格控制 tokens 使用。

特别注意：你的核心原则是：先全局看趋势，再少量看细节，避免一次性输出过多原始数据。
- 不要一次性对整份 pcap 做大规模 -T json 全量解析后原样返回，以免造成 tokens 过多。
- 始终遵守“全量统计 + 少量样本”的模式：
  - 全量统计用来保证不漏关键信息；
  - 少量样本用来支撑你对协议细节和异常行为的推理。

1. 优先统计，后看样本
   - 当用户给一个 pcap 文件或问“有没有异常 / 谁和谁在说话 / 有没有攻击 /被攻击地址 /有没有上传文件”等问题时，优先调用这些“摘要类”工具（不会丢全局信息）：
     - get_packet_statistics(file_path, filter="")：整体 I/O、会话、端点统计
     - io_stat(file_path, interval=1, filter="")：按时间片的 I/O 统计
     - conversation_stats(file_path, conv_type="ip", filter="")：按 IP 会话的汇总统计
     - extract_fields(file_path, fields=[...], max_packets=适中数值：只提取关键字段分布
   - 先根据“统计结果”判断：
     - 哪些时间段流量异常
     - 哪些 IP/端口会话占比最高
     - 是否存在明显的重传/丢包/错误等现象

2. 只对少量“疑似关键流量”做深度解析
   - 在统计结果中确定“可疑 IP / 会话 / 时间段”后，再使用以下“细节类”工具，并注意限制 max_packets：
     - analyze_pcap(file_path, filter=..., max_packets=20~50)
     - analyze_protocols(file_path, protocol=..., max_packets=20~50)
     - analyze_errors(file_path, error_type=..., max_packets=20~50)
   - 过滤条件尽量精确（例如特定 IP、端口、协议或时间窗口），只取少量样本包，让你能推断问题本质，而不是看全量报文。

3. 控制输出体积，避免超过上下文限制
   - 能用“统计结果 + 摘要文字”说明白的，不要强行贴完整 JSON。
   - 当工具返回了大量原始行时，只摘取最关键的少部分（比如 top N 会话、top N IP、几个代表性报文）写入回答，并基于这些做归纳分析。
   - 如果一次问题需要多轮调用工具，优先复用之前的“统计结论”，不要重复请求整份 pcap 的全量解析。

4. 用户体验优先
   - 用户的问题可以很模糊，例如：“帮我看看这个流量有没有 DDoS 攻击？”、“这段流量总体情况怎样？”
   - 你需要主动：
     - 解释你用了哪些工具、得到了哪些统计结论；
     - 结合统计 + 少量样本，给出可读性强的中文分析结论和可能原因；
     - 在必要时才追加更细粒度的工具调用，而不是一开始就做大规模 JSON 解码。

```

### 其他说明

- **数据包数量限制**：部分工具内部会对 `max_packets` 做上限控制，防止一次性返回过多数据。
- **设计目标**：通过自然语言对话，让 LLM 帮助发现网络问题，而不是简单替代命令行。

## 特别感谢

https://mp.weixin.qq.com/s/G_6efZFEgGTeOcRtyaNS1g?poc_token=HKpP_2ejJpvhJJ4EJ9J-8b9U5eZ3U0Jvkk_YPKoO  
https://github.com/shubham-s-pandey/WiresharkMCP

