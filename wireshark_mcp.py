#!/usr/bin/env python3
import argparse
import json
import logging
import os
import subprocess
import sys
import signal
import platform
from typing import Dict, List, Optional, Union
import uvicorn
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.requests import Request
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from datetime import datetime

from mcp.server import Server
from mcp.server.fastmcp import FastMCP
from mcp.types import Tool

# 自定义日志格式
class CustomFormatter(logging.Formatter):
    """自定义日志格式器"""
    
    grey = "\x1b[38;21m"
    blue = "\x1b[38;5;39m"
    yellow = "\x1b[38;5;226m"
    red = "\x1b[38;5;196m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    def __init__(self):
        super().__init__()
        self.fmt = "%(asctime)s %(levelname)s: %(message)s"
        
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%H:%M:%S")
        return formatter.format(record)

# 配置日志
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

class WiresharkMCP:
    def __init__(self, tshark_path: str = "tshark"):
        """初始化 Wireshark MCP 服务器
        
        Args:
            tshark_path: tshark 可执行文件的路径
        """
        # 验证 tshark_path 参数
        if not isinstance(tshark_path, str) or not tshark_path.strip():
            raise ValueError("tshark_path 必须是非空字符串")

        self.tshark_path = tshark_path.strip()
        self._verify_tshark()
        self.running = True

    def _validate_file_path(self, file_path: str) -> None:
        """验证文件路径的安全性和有效性"""
        if not isinstance(file_path, str) or not file_path.strip():
            raise ValueError("文件路径不能为空")

        file_path = file_path.strip()

        # 防止路径遍历攻击（允许绝对路径，但禁止 .. ）
        if ".." in file_path:
            raise ValueError("文件路径不能包含 '..' 序列")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"找不到文件: {file_path}")

        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"无法读取文件: {file_path}")

    def _validate_max_packets(self, max_packets: int) -> int:
        """验证和标准化 max_packets 参数"""
        if not isinstance(max_packets, int):
            try:
                max_packets = int(max_packets)
            except (ValueError, TypeError):
                raise ValueError("max_packets 必须是整数")

        if max_packets <= 0:
            raise ValueError("max_packets 必须大于 0")

        # 防止过大的值导致系统问题
        if max_packets > 50000:
            logger.warning(f"max_packets 值 {max_packets} 过大，已限制为 50000")
            max_packets = 50000

        return max_packets

    def _validate_filter_expression(self, filter_expr: str) -> str:
        """验证过滤器表达式的基本安全性"""
        if not isinstance(filter_expr, str):
            raise ValueError("过滤器表达式必须是字符串")

        filter_expr = filter_expr.strip()

        # 基本的安全检查，防止命令注入（仅告警，不强制阻止）
        dangerous_chars = [";", "&", "|", "`", "$", "()", "{}", ">"]
        if any(char in filter_expr for char in dangerous_chars):
            logger.warning(f"过滤器表达式包含可能危险的字符: {filter_expr}")

        return filter_expr

    def _verify_tshark(self):
        """验证 tshark 是否可用"""
        try:
            subprocess.run([self.tshark_path, "-v"], 
                         capture_output=True, 
                         check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"tshark 验证失败: {e}")
            raise
        except FileNotFoundError:
            logger.error(f"找不到 tshark: {self.tshark_path}")
            raise

    def _format_json_output(self, json_str: str, max_packets: int = 5000) -> str:
        """格式化 JSON 输出为易读形式，并限制数据包数量
        
        Args:
            json_str: JSON 字符串
            max_packets: 最大数据包数量
        """
        try:
            # 基础元数据
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "tshark_version": self._get_tshark_version(),
                "max_packets": max_packets
            }
            
            # 如果输入为空
            if not json_str.strip():
                return json.dumps({
                    "status": "no_data",
                    "metadata": metadata,
                    "message": "没有找到匹配的数据包",
                    "details": {
                        "possible_reasons": [
                            "过滤器可能过于严格",
                            "数据包中没有相关协议",
                            "文件可能为空"
                        ]
                    }
                }, ensure_ascii=False, indent=2)
                
            # 尝试解析 JSON
            if json_str.startswith("[") or json_str.startswith("{"):
                data = json.loads(json_str)
                
                if isinstance(data, list):
                    # 添加数据包统计信息
                    packet_stats = {
                        "total_packets": len(data),
                        "returned_packets": min(len(data), max_packets),
                        "truncated": len(data) > max_packets
                    }
                    
                    # 如果需要截断
                    if packet_stats["truncated"]:
                        data = data[:max_packets]
                        
                    return json.dumps({
                        "status": "success",
                        "metadata": metadata,
                        "statistics": packet_stats,
                        "data": data
                    }, ensure_ascii=False, indent=2)
                    
                # 如果是对象，直接包装
                return json.dumps({
                    "status": "success",
                    "metadata": metadata,
                    "data": data
                }, ensure_ascii=False, indent=2)
            
            # 处理非 JSON 格式的输出
            return json.dumps({
                "status": "success",
                "metadata": metadata,
                "data": json_str.strip().split("\n")
            }, ensure_ascii=False, indent=2)
            
        except json.JSONDecodeError as e:
            return json.dumps({
                "status": "error",
                "metadata": metadata,
                "error": {
                    "type": "json_decode_error",
                    "message": str(e),
                    "raw_data": json_str[:200] + "..." if len(json_str) > 200 else json_str
                }
            }, ensure_ascii=False, indent=2)
            
    def _get_tshark_version(self) -> str:
        """获取 tshark 版本信息"""
        try:
            proc = subprocess.run([self.tshark_path, "-v"],
                                capture_output=True,
                                text=True,
                                check=True)
            version_line = proc.stdout.split("\n")[0]
            return version_line.strip()
        except Exception:
            return "unknown"

    def _run_tshark_command(self, cmd: List[str], max_packets: int = 5000) -> str:
        """运行 tshark 命令并处理输出
        
        Args:
            cmd: tshark 命令参数列表
            max_packets: 最大数据包数量
        """
        try:
            # 统一校验 max_packets，避免异常或过大值
            try:
                max_packets = self._validate_max_packets(max_packets)
            except ValueError as ve:
                return json.dumps({
                    "status": "error",
                    "metadata": {
                        "timestamp": datetime.now().isoformat()
                    },
                    "error": {
                        "type": "invalid_parameter",
                        "message": str(ve)
                    }
                }, ensure_ascii=False, indent=2)

            # 确保 max_packets 至少为 1
            if "-c" in cmd:
                c_index = cmd.index("-c")
                if c_index + 1 < len(cmd):
                    packet_count = max(1, int(cmd[c_index + 1]))
                    cmd[c_index + 1] = str(packet_count)
            
            proc = subprocess.run(cmd,
                                capture_output=True,
                                text=True,
                                check=True)
            return self._format_json_output(proc.stdout, max_packets)
        except subprocess.CalledProcessError as e:
            error_msg = f"tshark 命令执行失败: {e.stderr if e.stderr else str(e)}"
            logger.error(error_msg)
            return json.dumps({
                "error": error_msg,
                "command": " ".join(cmd),
                "建议": "请检查文件路径是否正确，以及是否有读取权限"
            }, ensure_ascii=False, indent=2)

    def capture_live(self, 
                    interface: str, 
                    duration: int = 10,
                    filter: str = "",
                    max_packets: int = 100) -> str:
        """实时抓包
        
        Args:
            interface: 网络接口名称
            duration: 抓包持续时间(秒)
            filter: 抓包过滤器表达式 (BPF)
            max_packets: 最大数据包数量
        """
        # 参数校验，避免直接抛 Python 异常
        if not isinstance(interface, str) or not interface.strip():
            return json.dumps({
                "status": "error",
                "error": {
                    "type": "invalid_parameter",
                    "message": "网络接口名称不能为空"
                }
            }, ensure_ascii=False, indent=2)

        if not isinstance(duration, int) or duration <= 0 or duration > 3600:
            return json.dumps({
                "status": "error",
                "error": {
                    "type": "invalid_parameter",
                    "message": "持续时间必须是 1-3600 秒之间的整数"
                }
            }, ensure_ascii=False, indent=2)

        try:
            max_packets = self._validate_max_packets(max_packets)
            if filter:
                filter = self._validate_filter_expression(filter)
        except ValueError as e:
            return json.dumps({
                "status": "error",
                "error": {
                    "type": "invalid_parameter",
                    "message": str(e)
                }
            }, ensure_ascii=False, indent=2)

        cmd = [
            self.tshark_path,
            "-i", interface.strip(),
            "-a", f"duration:{duration}",
            "-T", "json",
            "-c", str(max_packets)
        ]
        if filter:
            cmd.extend(["-f", filter])
            
        return self._run_tshark_command(cmd, max_packets)

    def list_interfaces(self) -> List[Dict[str, str]]:
        """列出可用的网络接口"""
        cmd = [self.tshark_path, "-D"]
        try:
            proc = subprocess.run(cmd,
                                  capture_output=True,
                                  text=True,
                                  check=True)
            interfaces = []
            for line in proc.stdout.splitlines():
                if line.strip():
                    # tshark -D 输出示例:
                    # "1. eth0 [Ethernet]"
                    # "2. any"
                    if ". " in line:
                        interface_part = line.split(". ", 1)[1].strip()
                        if "[" in interface_part and interface_part.endswith("]"):
                            parts = interface_part.rsplit(" [", 1)
                            iface = parts[0].strip()
                            desc = parts[1].rstrip("]").strip()
                        else:
                            iface = interface_part.strip()
                            desc = ""
                        interfaces.append({"name": iface, "description": desc})
            return interfaces
        except subprocess.CalledProcessError as e:
            logger.error(f"获取接口列表失败: {e}")
            return []
        except Exception as e:
            logger.error(f"解析接口列表时出错: {e}")
            return []

    def analyze_pcap(self, 
                    file_path: str,
                    filter: str = "",
                    max_packets: int = 100) -> str:
        """分析 pcap 文件
        
        Args:
            file_path: pcap 文件路径
            filter: 显示过滤器表达式
            max_packets: 最大数据包数量
        """
        try:
            self._validate_file_path(file_path)
            max_packets = self._validate_max_packets(max_packets)
            if filter:
                filter = self._validate_filter_expression(filter)
        except (ValueError, FileNotFoundError, PermissionError) as e:
            return json.dumps({
                "status": "error",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path
                },
                "error": {
                    "type": "validation_error",
                    "message": str(e)
                }
            }, ensure_ascii=False, indent=2)

        cmd = [
            self.tshark_path,
            "-r", file_path,
            "-T", "json",
            "-c", str(max_packets)
        ]
        if filter:
            cmd.extend(["-Y", filter])

        return self._run_tshark_command(cmd, max_packets)

    def get_protocols(self) -> List[str]:
        """获取支持的协议列表"""
        cmd = [self.tshark_path, "-G", "protocols"]
        try:
            proc = subprocess.run(cmd,
                                  capture_output=True,
                                  text=True,
                                  check=True)
            protocols: List[str] = []
            for line in proc.stdout.splitlines():
                if line.strip():
                    # 格式: "protocol_name<TAB>description"
                    parts = line.split("\t")
                    if len(parts) >= 1:
                        protocols.append(parts[0].strip())
            return protocols
        except subprocess.CalledProcessError as e:
            logger.error(f"获取协议列表失败: {e}")
            return []
        except Exception as e:
            logger.error(f"解析协议列表时出错: {e}")
            return []

    def get_packet_statistics(self, 
                            file_path: str,
                            filter: str = "") -> str:
        """获取数据包统计信息
        
        Args:
            file_path: pcap 文件路径
            filter: 显示过滤器表达式
        """
        if not os.path.exists(file_path):
            return json.dumps({
                "status": "error",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path
                },
                "error": {
                    "type": "file_not_found",
                    "message": f"找不到文件: {file_path}"
                }
            }, ensure_ascii=False, indent=2)

        if filter:
            try:
                filter = self._validate_filter_expression(filter)
            except ValueError as ve:
                return json.dumps({
                    "status": "error",
                    "metadata": {
                        "timestamp": datetime.now().isoformat(),
                        "file_path": file_path
                    },
                    "error": {
                        "type": "invalid_parameter",
                        "message": str(ve)
                    }
                }, ensure_ascii=False, indent=2)

        cmd = [
            self.tshark_path,
            "-r", file_path,
            "-q",
            "-z", "io,stat,1",   # 1秒间隔的 I/O 统计
            "-z", "conv,ip",     # IP 会话统计
            "-z", "endpoints,ip" # IP 端点统计
        ]
        if filter:
            cmd.extend(["-Y", filter])

        try:
            proc = subprocess.run(cmd,
                                  capture_output=True,
                                  text=True,
                                  check=True)

            stats_lines = proc.stdout.strip().split("\n")
            return json.dumps({
                "status": "success",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path,
                    "filter": filter,
                    "tshark_version": self._get_tshark_version()
                },
                "statistics": {
                    "raw_output": stats_lines,
                    "summary": "数据包统计信息已生成"
                }
            }, ensure_ascii=False, indent=2)
        except subprocess.CalledProcessError as e:
            error_msg = f"tshark 统计命令执行失败: {e.stderr if e.stderr else str(e)}"
            logger.error(error_msg)
            return json.dumps({
                "status": "error",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path,
                    "filter": filter
                },
                "error": {
                    "type": "tshark_command_failed",
                    "message": error_msg,
                    "command": " ".join(cmd)
                }
            }, ensure_ascii=False, indent=2)
    def io_stat(self,
                file_path: str,
                interval: int = 1,
                filter: str = "") -> str:
        """基于 tshark 的 I/O 统计 (-z io,stat) 生成功能

        Args:
            file_path: pcap/pcapng 文件路径
            interval: 统计时间间隔，单位秒
            filter: 显示过滤器表达式 (tshark -Y)
        """
        try:
            self._validate_file_path(file_path)
            if interval <= 0:
                interval = 1
            if filter:
                filter = self._validate_filter_expression(filter)
        except (ValueError, FileNotFoundError, PermissionError) as e:
            return json.dumps({
                "status": "error",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path
                },
                "error": {
                    "type": "validation_error",
                    "message": str(e)
                }
            }, ensure_ascii=False, indent=2)

        # 参考 tshark 手册 -z io,stat,N 统计 I/O 信息
        # 见 [tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html)
        cmd = [
            self.tshark_path,
            "-r", file_path,
            "-q",
            "-z", f"io,stat,{interval}"
        ]
        if filter:
            cmd.extend(["-Y", filter])

        try:
            proc = subprocess.run(cmd,
                                  capture_output=True,
                                  text=True,
                                  check=True)
            lines = proc.stdout.strip().split("\n")
            return json.dumps({
                "status": "success",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path,
                    "interval": interval,
                    "filter": filter,
                    "tshark_version": self._get_tshark_version()
                },
                "statistics": {
                    "raw_output": lines,
                    "summary": "I/O 统计信息已生成"
                }
            }, ensure_ascii=False, indent=2)
        except subprocess.CalledProcessError as e:
            error_msg = f"tshark I/O 统计命令执行失败: {e.stderr if e.stderr else str(e)}"
            logger.error(error_msg)
            return json.dumps({
                "status": "error",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path,
                    "interval": interval,
                    "filter": filter
                },
                "error": {
                    "type": "tshark_command_failed",
                    "message": error_msg,
                    "command": " ".join(cmd)
                }
            }, ensure_ascii=False, indent=2)

    def conversation_stats(self,
                           file_path: str,
                           conv_type: str = "ip",
                           filter: str = "") -> str:
        """基于 tshark 的会话统计 (-z conv,XXX)

        Args:
            file_path: pcap/pcapng 文件路径
            conv_type: 会话类型，例如 "ip", "tcp", "udp", "eth"
            filter: 显示过滤器表达式 (tshark -Y)
        """
        try:
            self._validate_file_path(file_path)
            if filter:
                filter = self._validate_filter_expression(filter)
        except (ValueError, FileNotFoundError, PermissionError) as e:
            return json.dumps({
                "status": "error",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path
                },
                "error": {
                    "type": "validation_error",
                    "message": str(e)
                }
            }, ensure_ascii=False, indent=2)

        conv_type = (conv_type or "ip").lower()

        # 参考 tshark 手册 -z conv,XXX 统计会话信息
        # 见 [tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html)
        cmd = [
            self.tshark_path,
            "-r", file_path,
            "-q",
            "-z", f"conv,{conv_type}"
        ]
        if filter:
            cmd.extend(["-Y", filter])

        try:
            proc = subprocess.run(cmd,
                                  capture_output=True,
                                  text=True,
                                  check=True)
            lines = proc.stdout.strip().split("\n")
            return json.dumps({
                "status": "success",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path,
                    "conv_type": conv_type,
                    "filter": filter,
                    "tshark_version": self._get_tshark_version()
                },
                "statistics": {
                    "raw_output": lines,
                    "summary": "会话统计信息已生成"
                }
            }, ensure_ascii=False, indent=2)
        except subprocess.CalledProcessError as e:
            error_msg = f"tshark 会话统计命令执行失败: {e.stderr if e.stderr else str(e)}"
            logger.error(error_msg)
            return json.dumps({
                "status": "error",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path,
                    "conv_type": conv_type,
                    "filter": filter
                },
                "error": {
                    "type": "tshark_command_failed",
                    "message": error_msg,
                    "command": " ".join(cmd)
                }
            }, ensure_ascii=False, indent=2)

    def extract_fields(self,
                      file_path: str,
                      fields: List[str],
                      filter: str = "",
                      max_packets: int = 5000) -> str:
        """提取特定字段信息
        
        Args:
            file_path: pcap 文件路径
            fields: 要提取的字段列表
            filter: 显示过滤器表达式
            max_packets: 最大数据包数量
        """
        try:
            self._validate_file_path(file_path)
            max_packets = self._validate_max_packets(max_packets)
            if filter:
                filter = self._validate_filter_expression(filter)
        except (ValueError, FileNotFoundError, PermissionError) as e:
            return json.dumps({
                "status": "error",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path,
                    "fields": fields,
                    "filter": filter
                },
                "error": {
                    "type": "validation_error",
                    "message": str(e)
                }
            }, ensure_ascii=False, indent=2)

        cmd = [
            self.tshark_path,
            "-r", file_path,
            "-T", "fields"
        ]
        
        for field in fields:
            cmd.extend(["-e", field])
            
        if filter:
            cmd.extend(["-Y", filter])
            
        if max_packets > 0:
            cmd.extend(["-c", str(max_packets)])
        
        result = self._run_tshark_command(cmd, max_packets)
        
        # 处理字段提取结果
        if isinstance(result, str) and not result.startswith("{"):
            lines = [line.strip() for line in result.splitlines() if line.strip()]
            if not lines:
                return json.dumps({
                    "status": "no_data",
                    "metadata": {
                        "timestamp": datetime.now().isoformat(),
                        "file_path": file_path,
                        "fields": fields,
                        "filter": filter
                    },
                    "message": "没有找到匹配的数据包",
                    "details": {
                        "fields_requested": fields,
                        "filter_applied": filter or "无"
                    }
                }, ensure_ascii=False, indent=2)
                
            # 统计字段值出现次数
            from collections import Counter
            counter = Counter(lines)
            total = len(lines)
            top10 = counter.most_common(10)
            
            # 格式化统计结果
            stats = {
                "status": "success",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path,
                    "fields": fields,
                    "filter": filter
                },
                "statistics": {
                    "total_values": total,
                    "unique_values": len(counter),
                    "top_values": [
                        {
                            "value": k,
                            "count": v,
                            "percentage": round(v/total*100, 2),
                            "frequency": f"{v}/{total}"
                        } for k, v in top10
                    ]
                },
                "summary": {
                    "most_common": top10[0][0] if top10 else None,
                    "most_common_count": top10[0][1] if top10 else 0
                }
            }
            
            return json.dumps(stats, ensure_ascii=False, indent=2)
            
        return result

    def analyze_protocols(self,
                        file_path: str,
                        protocol: str = "",
                        max_packets: int = 100) -> str:
        """分析特定协议的数据包
        
        Args:
            file_path: pcap 文件路径
            protocol: 协议名称
            max_packets: 最大数据包数量
        """
        if not os.path.exists(file_path):
            return json.dumps({
                "error": f"找不到文件: {file_path}",
                "建议": "请检查文件路径是否正确"
            }, ensure_ascii=False, indent=2)
            
        cmd = [
            self.tshark_path,
            "-r", file_path,
            "-T", "json",
            "-c", str(max_packets)
        ]
        
        if protocol:
            # 直接使用协议名称作为过滤器
            cmd.extend(["-Y", protocol.lower()])

        # 统一交给 _run_tshark_command 处理输出和结构化
        return self._run_tshark_command(cmd, max_packets)

    def analyze_errors(self,
                      file_path: str,
                      error_type: str = "all",
                      max_packets: int = 5000) -> str:
        """分析数据包中的错误
        
        Args:
            file_path: pcap 文件路径
            error_type: 错误类型 (all/malformed/tcp/duplicate_ack/lost_segment)
            max_packets: 最大数据包数量
        """
        if not os.path.exists(file_path):
            return json.dumps({
                "status": "error",
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "file_path": file_path
                },
                "error": {
                    "type": "file_not_found",
                    "message": f"找不到文件: {file_path}",
                    "suggestion": "请检查文件路径是否正确"
                }
            }, ensure_ascii=False, indent=2)
        
        # 根据错误类型设置过滤器
        filters = {
            "all": "(_ws.malformed) or (tcp.analysis.flags) or (tcp.analysis.retransmission) or (tcp.analysis.duplicate_ack) or (tcp.analysis.lost_segment)",
            "malformed": "_ws.malformed",
            "tcp": "tcp.analysis.flags",
            "retransmission": "tcp.analysis.retransmission",
            "duplicate_ack": "tcp.analysis.duplicate_ack",
            "lost_segment": "tcp.analysis.lost_segment"
        }
        
        filter_expr = filters.get(error_type, filters["all"])
        
        cmd = [
            self.tshark_path,
            "-r", file_path,
            "-Y", filter_expr,
            "-T", "json",
            "-c", str(max_packets)
        ]
        # 统一交给 _run_tshark_command 处理输出和结构化
        return self._run_tshark_command(cmd, max_packets)

    def stop(self):
        """停止服务器"""
        self.running = False

def create_mcp_server(wireshark: WiresharkMCP) -> FastMCP:
    """创建 MCP 服务器实例"""
    mcp = FastMCP(
        "Wireshark MCP",
        server_url="http://127.0.0.1:3000"
    )
    
    # 存储服务器实例
    create_mcp_server.instance = mcp
    create_mcp_server.wireshark = wireshark
    
    @mcp.tool()
    def list_interfaces() -> List[Dict[str, str]]:
        """列出所有可用的网络接口"""
        return wireshark.list_interfaces()
            
    @mcp.tool()
    def capture_live(interface: str,
                    duration: int = 10,
                    filter: str = "",
                    max_packets: int = 100) -> str:
        """实时抓包分析"""
        return wireshark.capture_live(interface, duration, filter, max_packets)
            
    @mcp.tool()
    def analyze_pcap(file_path: str,
                    filter: str = "",
                    max_packets: int = 100) -> str:
        """分析 pcap 文件"""
        return wireshark.analyze_pcap(file_path, filter, max_packets)

    @mcp.tool()
    def get_protocols() -> List[str]:
        """获取支持的协议列表"""
        return wireshark.get_protocols()

    @mcp.tool()
    def get_packet_statistics(file_path: str,
                            filter: str = "") -> str:
        """获取数据包统计信息"""
        return wireshark.get_packet_statistics(file_path, filter)

    @mcp.tool()
    def extract_fields(file_path: str,
                      fields: List[str],
                      filter: str = "",
                      max_packets: int = 5000) -> str:
        """提取特定字段信息"""
        return wireshark.extract_fields(file_path, fields, filter, max_packets)

    @mcp.tool()
    def analyze_protocols(file_path: str,
                        protocol: str = "",
                        max_packets: int = 100) -> str:
        """分析特定协议的数据包"""
        return wireshark.analyze_protocols(file_path, protocol, max_packets)
        
    @mcp.tool()
    def analyze_errors(file_path: str,
                      error_type: str = "all",
                      max_packets: int = 5000) -> str:
        """分析数据包中的错误"""
        return wireshark.analyze_errors(file_path, error_type, max_packets)

    @mcp.tool()
    def io_stat(file_path: str,
                interval: int = 1,
                filter: str = "") -> str:
        """基于 tshark -z io,stat 的 I/O 统计工具

        Args:
            file_path: pcap/pcapng 文件路径
            interval: 统计时间间隔（秒）
            filter: 显示过滤器表达式
        """
        return wireshark.io_stat(file_path, interval, filter)

    @mcp.tool()
    def conversation_stats(file_path: str,
                           conv_type: str = "ip",
                           filter: str = "") -> str:
        """基于 tshark -z conv,XXX 的会话统计工具

        Args:
            file_path: pcap/pcapng 文件路径
            conv_type: 会话类型，例如 "ip", "tcp", "udp", "eth"
            filter: 显示过滤器表达式
        """
        return wireshark.conversation_stats(file_path, conv_type, filter)
    
    return mcp

# 全局变量存储服务器实例
server_instance = None

def cleanup():
    """清理资源"""
    try:
        if hasattr(create_mcp_server, 'wireshark'):
            create_mcp_server.wireshark.stop()
    except Exception as e:
        # 仅在调试级别记录清理错误
        logger.debug(f"清理资源时发生错误: {e}")

def handle_exit(signum, frame):
    """处理退出信号"""
    global server_instance
    
    try:
        logger.info("正在关闭服务器...")
        cleanup()
        
        # 如果服务器实例存在，尝试停止它
        if server_instance:
            server_instance.should_exit = True
    except Exception as e:
        # 仅在调试级别记录退出错误
        logger.debug(f"退出时发生错误: {e}")
    # 让 uvicorn 自己优雅退出，不强制 os._exit

def homepage(request: Request) -> HTMLResponse:
    """根路由处理器"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Wireshark MCP 服务器</title>
        <style>
            :root {
                --primary-color: #1976d2;
                --success-color: #2e7d32;
                --background-color: #f5f5f5;
                --card-background: white;
                --text-color: #333;
                --border-color: #ddd;
            }
            
            body { 
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                margin: 0;
                padding: 0;
                background: var(--background-color);
                color: var(--text-color);
                line-height: 1.6;
            }
            
            .container { 
                max-width: 1000px; 
                margin: 40px auto;
                padding: 30px;
                background: var(--card-background);
                border-radius: 12px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            
            .header {
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid var(--border-color);
            }
            
            .header h1 {
                color: var(--primary-color);
                margin: 0;
                font-size: 2.2em;
            }
            
            .status {
                padding: 20px;
                background: #e8f5e9;
                border-radius: 8px;
                margin: 20px 0;
                color: var(--success-color);
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .status::before {
                content: "●";
                color: var(--success-color);
                font-size: 1.5em;
            }
            
            .tools-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }
            
            .tool { 
                padding: 20px;
                background: white;
                border: 1px solid var(--border-color);
                border-radius: 8px;
                transition: all 0.3s ease;
            }
            
            .tool:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }
            
            .tool h3 { 
                margin: 0 0 10px 0;
                color: var(--primary-color);
                font-size: 1.2em;
            }
            
            .tool p {
                margin: 0;
                color: #666;
                font-size: 0.95em;
            }
            
            .tool .params {
                margin-top: 10px;
                font-size: 0.9em;
                color: #888;
            }
            
            .info-section {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 2px solid var(--border-color);
            }
            
            .info-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }
            
            .info-card {
                padding: 15px;
                background: #f8f9fa;
                border-radius: 6px;
                border-left: 4px solid var(--primary-color);
            }
            
            .info-card h4 {
                margin: 0 0 10px 0;
                color: var(--primary-color);
            }
            
            .info-card p {
                margin: 0;
                font-size: 0.9em;
                color: #666;
            }
            
            @media (max-width: 768px) {
                .container {
                    margin: 20px;
                    padding: 20px;
                }
                
                .tools-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Wireshark MCP 服务器</h1>
            </div>
            
            <div class="status">
                服务器运行正常
            </div>
            
            <h2>可用工具</h2>
            <div class="tools-grid">
                <div class="tool">
                    <h3>list_interfaces</h3>
                    <p>列出所有可用的网络接口</p>
                    <div class="params">返回类型: List[Dict[str, str]]</div>
                </div>
                
                <div class="tool">
                    <h3>capture_live</h3>
                    <p>实时抓包分析</p>
                    <div class="params">参数: interface, duration, filter, max_packets</div>
                </div>
                
                <div class="tool">
                    <h3>analyze_pcap</h3>
                    <p>分析 pcap 文件内容</p>
                    <div class="params">参数: file_path, filter, max_packets</div>
                </div>
                
                <div class="tool">
                    <h3>get_protocols</h3>
                    <p>获取支持的协议列表</p>
                    <div class="params">返回类型: List[str]</div>
                </div>
                
                <div class="tool">
                    <h3>get_packet_statistics</h3>
                    <p>获取数据包统计信息</p>
                    <div class="params">参数: file_path, filter</div>
                </div>
                
                <div class="tool">
                    <h3>extract_fields</h3>
                    <p>提取数据包中的特定字段</p>
                    <div class="params">参数: file_path, fields, filter, max_packets</div>
                </div>
                
                <div class="tool">
                    <h3>analyze_protocols</h3>
                    <p>分析特定协议的数据包</p>
                    <div class="params">参数: file_path, protocol, max_packets</div>
                </div>
                
                <div class="tool">
                    <h3>analyze_errors</h3>
                    <p>分析数据包中的错误</p>
                    <div class="params">参数: file_path, error_type, max_packets</div>
                </div>
            </div>
            
            <div class="info-section">
                <h2>系统信息</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <h4>服务器配置</h4>
                        <p>端口: 3000</p>
                        <p>地址: http://127.0.0.1:3000</p>
                    </div>
                    
                    <div class="info-card">
                        <h4>数据限制</h4>
                        <p>默认最大数据包数: 5000</p>
                        <p>支持过滤器表达式</p>
                    </div>
                    
                    <div class="info-card">
                        <h4>LLM 分析</h4>
                        <p>已配置为中文回复</p>
                        <p>支持智能分析和数据统计</p>
                    </div>
                    
                    <div class="info-card">
                        <h4>帮助信息</h4>
                        <p>查看 tshark 文档获取更多过滤器语法</p>
                        <p>支持 pcap/pcapng 格式</p>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html_content)

async def root_redirect(request: Request):
    """将根路径重定向到状态页面"""
    return RedirectResponse(url="/status")

def get_system_info() -> Dict[str, str]:
    """获取系统信息"""
    info = {
        "python_version": platform.python_version(),
        "os_platform": platform.platform(),
        "tshark_version": "未知"
    }
    
    try:
        # 获取 tshark 版本
        proc = subprocess.run(["tshark", "-v"],
                            capture_output=True,
                            text=True,
                            check=True)
        info["tshark_version"] = proc.stdout.split("\n")[0].strip()
    except Exception:
        pass
        
    return info

def print_banner(system_info: Dict[str, str]):
    """打印启动横幅"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    Wireshark MCP 服务器启动                      ║
╠══════════════════════════════════════════════════════════════════╣
║ 系统信息:                                                        ║
║ • Python: {system_info['python_version']}                        
║ • 操作系统: {system_info['os_platform']}                        
║ • TShark: {system_info['tshark_version']}                       
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def main():
    global server_instance
    
    parser = argparse.ArgumentParser(description="Wireshark MCP 服务器")
    parser.add_argument("--tshark-path",
                       default="tshark",
                       help="tshark 可执行文件路径")
    parser.add_argument("--host",
                       default="127.0.0.1",
                       help="服务器主机地址")
    parser.add_argument("--port",
                       type=int,
                       default=3000,
                       help="服务器端口")
    args = parser.parse_args()
    
    # 获取系统信息并打印横幅
    system_info = get_system_info()
    print_banner(system_info)
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    try:
        wireshark = WiresharkMCP(args.tshark_path)
        mcp = create_mcp_server(wireshark)
        
        # 配置中间件
        middleware = [
            Middleware(CORSMiddleware,
                      allow_origins=["*"],
                      allow_methods=["*"],
                      allow_headers=["*"])
        ]
        
        # 创建 Starlette 应用并配置路由
        routes = [
            Route("/status", homepage),
            Mount("/", app=mcp.sse_app())
        ]
        
        app = Starlette(
            routes=routes,
            middleware=middleware
        )
        
        logger.info(f"服务器地址: http://{args.host}:{args.port}")
        logger.info(f"状态页面: http://{args.host}:{args.port}/status")
        logger.info(f"SSE 端点: http://{args.host}:{args.port}/")
        
        # 配置 uvicorn 服务器
        config = uvicorn.Config(
            app,
            host=args.host,
            port=args.port,
            log_level="info"
        )
        server_instance = uvicorn.Server(config)
        server_instance.run()
        
    except Exception as e:
        logger.error(f"服务器启动失败: {e}")
        cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main() 