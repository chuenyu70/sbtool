#!/usr/bin/env python3
"""sbtool-server - sing-box 配置管理后端"""

import json
import os
import re
import subprocess
import time
import uuid
import base64
from urllib.parse import unquote
import hashlib
from pathlib import Path
from typing import Optional

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="sbtool-server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
CONFIGS_DIR = BASE_DIR / "configs"
SUBS_DIR = BASE_DIR / "subscriptions"
STATIC_DIR = BASE_DIR / "static"
SINGBOX_CONFIG = Path("/root/singbox/config.json")
SINGBOX_START = Path("/root/singbox/start.sh")
SINGBOX_BIN = "sing-box"

CONFIGS_DIR.mkdir(exist_ok=True)
SUBS_DIR.mkdir(exist_ok=True)

# ============ 地区映射 ============
REGION_MAP = {
    "SEA": "🇸🇬 新加坡", "SIN": "🇸🇬 新加坡", "SG": "🇸🇬 新加坡",
    "FRA": "🇩🇪 德国", "DE": "🇩🇪 德国",
    "SJC": "🇺🇸 美国", "LAX": "🇺🇸 美国", "US": "🇺🇸 美国",
    "JP": "🇯🇵 日本", "TYO": "🇯🇵 日本", "NRT": "🇯🇵 日本",
    "HK": "🇭🇰 香港", "HKG": "🇭🇰 香港",
    "KR": "🇰🇷 韩国", "ICN": "🇰🇷 韩国",
    "TW": "🇹🇼 台湾", "TPE": "🇹🇼 台湾",
    "GB": "🇬🇧 英国", "UK": "🇬🇧 英国", "LON": "🇬🇧 英国",
    "NL": "🇳🇱 荷兰", "AMS": "🇳🇱 荷兰",
    "CA": "🇨🇦 加拿大", "AU": "🇦🇺 澳大利亚", "SYD": "🇦🇺 澳大利亚",
    "IN": "🇮🇳 印度", "TH": "🇹🇭 泰国", "BKK": "🇹🇭 泰国",
    "VN": "🇻🇳 越南", "MY": "🇲🇾 马来西亚", "KUL": "🇲🇾 马来西亚",
    "ID": "🇮🇩 印尼", "PH": "🇵🇭 菲律宾",
    "RU": "🇷🇺 俄罗斯", "TR": "🇹🇷 土耳其",
    "BR": "🇧🇷 巴西", "AE": "🇦🇪 阿联酋", "DXB": "🇦🇪 阿联酋",
}

# ============ 数据模型 ============
class SubCreate(BaseModel):
    name: str
    url: str

class ConfigData(BaseModel):
    name: str
    config: dict

# ============ 工具函数 ============
# IP 地区缓存
_ip_region_cache = {}

def get_region(tag: str, server: str = "") -> Optional[str]:
    # 1. 从 tag 中识别
    parts = tag.upper().replace("-", " ").replace("_", " ").split()
    for p in parts:
        if p in REGION_MAP:
            return REGION_MAP[p]
    # 2. 从 server IP 反查
    if server and server not in _ip_region_cache:
        try:
            import urllib.request
            resp = urllib.request.urlopen(f"http://ip-api.com/json/{server}?fields=countryCode", timeout=3)
            data = json.loads(resp.read())
            code = data.get("countryCode", "")
            _ip_region_cache[server] = code
        except Exception:
            _ip_region_cache[server] = ""
    code = _ip_region_cache.get(server, "")
    if code in REGION_MAP:
        return REGION_MAP[code]
    return None

def parse_clash_subscription(text: str) -> list[dict]:
    """解析 Clash/YAML 订阅"""
    nodes = []
    try:
        data = yaml.safe_load(text)
        proxies = data.get("proxies", [])
        for p in proxies:
            node = {
                "name": p.get("name", "unknown"),
                "type": p.get("type", ""),
                "server": p.get("server", ""),
                "port": p.get("port", 0),
            }
            if p.get("type") == "vmess":
                node["uuid"] = p.get("uuid", "")
                node["alterId"] = p.get("alterId", 0)
                node["cipher"] = p.get("cipher", "auto")
                node["network"] = p.get("network", "tcp")
                if p.get("ws-opts"):
                    node["wsPath"] = p["ws-opts"].get("path", "/")
                    node["wsHeaders"] = p["ws-opts"].get("headers", {})
            elif p.get("type") == "vless":
                node["uuid"] = p.get("uuid", "")
                node["network"] = p.get("network", "tcp")
                node["flow"] = p.get("flow", "")
                if p.get("ws-opts"):
                    node["wsPath"] = p["ws-opts"].get("path", "/")
            elif p.get("type") == "trojan":
                node["password"] = p.get("password", "")
            elif p.get("type") == "ss":
                node["cipher"] = p.get("cipher", "")
                node["password"] = p.get("password", "")
            nodes.append(node)
    except Exception:
        pass
    return nodes

def parse_v2ray_subscription(text: str) -> list[dict]:
    """解析 base64 编码的 V2Ray 订阅"""
    nodes = []
    try:
        decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        decoded = text
    for line in decoded.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            node = parse_single_v2ray_link(line)
            if node:
                nodes.append(node)
        except Exception:
            pass
    return nodes

def parse_single_v2ray_link(link: str) -> Optional[dict]:
    """解析单个 vmess:// vless:// trojan:// 等链接"""
    if link.startswith("vmess://"):
        try:
            b64 = link[8:]
            # 处理 URL 编码的 %3A 等
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
            data = json.loads(decoded)
            return {
                "name": data.get("ps", "unknown"),
                "type": "vmess",
                "server": data.get("add", ""),
                "port": int(data.get("port", 0)),
                "uuid": data.get("id", ""),
                "alterId": int(data.get("aid", 0)),
                "cipher": data.get("scy", "auto"),
                "network": data.get("net", "tcp"),
                "wsPath": unquote(data.get("path", "/")),
                "wsHeaders": {"Host": data.get("host", "")} if data.get("host") else {},
                "tls": data.get("tls", ""),
            }
        except Exception:
            pass
    elif link.startswith("vless://"):
        try:
            rest = link[8:]
            # vless://uuid@server:port?params#name
            m = re.match(r'([^@]+)@([^:]+):(\d+)\?(.+)#(.+)', rest)
            if m:
                uuid_str, server, port, params, name = m.groups()
                params_dict = dict(p.split("=", 1) for p in params.split("&") if "=" in p)
                return {
                    "name": name,
                    "type": "vless",
                    "server": server,
                    "port": int(port),
                    "uuid": uuid_str,
                    "network": params_dict.get("type", "tcp"),
                    "security": params_dict.get("security", "none"),
                    "flow": params_dict.get("flow", ""),
                    "wsPath": unquote(params_dict.get("path", "/")),
                    "wsHeaders": {"Host": params_dict.get("host", "")} if params_dict.get("host") else {},
                }
        except Exception:
            pass
    elif link.startswith("vmess://"):
        try:
            rest = link[9:]
            m = re.match(r'([^@]+)@([^:]+):(\d+)\??(.*)#(.+)', rest)
            if m:
                password, server, port, params, name = m.groups()
                return {
                    "name": name,
                    "type": "trojan",
                    "server": server,
                    "port": int(port),
                    "password": password,
                }
        except Exception:
            pass
    elif link.startswith("ss://"):
        try:
            rest = link[5:]
            # ss://base64@server:port#name or ss://method:password@server:port
            if "#" in rest:
                main, name = rest.split("#", 1)
            else:
                main, name = rest, "ss-node"
            if "@" in main:
                userinfo, hostpart = main.split("@", 1)
                try:
                    userinfo = base64.b64decode(userinfo).decode()
                except Exception:
                    pass
                method, password = userinfo.split(":", 1)
                server, port = hostpart.split(":", 1)
                return {
                    "name": name,
                    "type": "ss",
                    "server": server,
                    "port": int(port),
                    "cipher": method,
                    "password": password,
                }
        except Exception:
            pass
    elif link.startswith("hysteria2://") or link.startswith("hy2://"):
        try:
            rest = link.split("://", 1)[1]
            m = re.match(r'([^@]+)@([^:]+):(\d+)\??(.*)#(.+)', rest)
            if m:
                password, server, port, params, name = m.groups()
                return {
                    "name": name,
                    "type": "hysteria2",
                    "server": server,
                    "port": int(port),
                    "password": password,
                }
        except Exception:
            pass
    elif link.startswith("tuic://"):
        try:
            rest = link[7:]
            m = re.match(r'([^@]+)@([^:]+):(\d+)\??(.*)#(.+)', rest)
            if m:
                creds, server, port, params, name = m.groups()
                uuid_str, password = creds.split(":", 1) if ":" in creds else (creds, "")
                return {
                    "name": name,
                    "type": "tuic",
                    "server": server,
                    "port": int(port),
                    "uuid": uuid_str,
                    "password": password,
                }
        except Exception:
            pass
    return None

def nodes_to_singbox_outbounds(nodes: list[dict]) -> list[dict]:
    """将解析后的节点转为 sing-box outbounds。
    如果节点已经是完整的 sing-box 格式（有 server 和 server_port），直接使用。
    """
    outbounds = []
    for n in nodes:
        tag = n.get("name", n.get("tag", "unknown"))
        ntype = n.get("type", "")
        server = n.get("server", "")
        port = n.get("port", n.get("server_port", 0))

        # 如果节点已经是完整的 sing-box outbound 格式，直接使用
        if server and port and ntype in ("vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic"):
            ob = {
                "type": ntype,
                "tag": tag,
                "server": server,
                "server_port": port,
            }
            # 复制关键字段
            for k in ["uuid", "password", "method", "flow", "security", "alter_id", "network"]:
                if k in n:
                    ob[k] = n[k]
            if "transport" in n:
                ob["transport"] = n["transport"]
            elif n.get("network") == "ws":
                ob["transport"] = {"type": "ws", "path": n.get("wsPath", "/")}
                if n.get("wsHeaders", {}).get("Host"):
                    ob["transport"]["headers"] = {"Host": n["wsHeaders"]["Host"]}
            elif n.get("network") and n["network"] != "tcp":
                ob["transport"] = {"type": n["network"]}
            if "tls" in n:
                ob["tls"] = n["tls"]
            elif n.get("tls") == "tls" or n.get("security") in ("tls", "reality"):
                sni = n.get("sni", "")
                if not sni:
                    sni = n.get("wsHeaders", {}).get("Host", "")
                if not sni:
                    sni = server
                ob["tls"] = {"enabled": True, "server_name": sni}
            if ntype == "vmess":
                ob.setdefault("security", "auto")
                ob.setdefault("alter_id", n.get("alterId", n.get("alter_id", 0)))
            elif ntype == "shadowsocks":
                ob.setdefault("method", n.get("cipher", n.get("method", "aes-256-gcm")))
            outbounds.append(ob)
            continue

        if not server or not port:
            continue

        if ntype == "vmess":
            ob = {
                "type": "vmess",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": n.get("uuid", ""),
                "security": "auto",
                "alter_id": n.get("alterId", 0),
            }
            net = n.get("network", "")
            if net == "ws":
                ob["transport"] = {"type": "ws", "path": n.get("wsPath", "/")}
                if n.get("wsHeaders", {}).get("Host"):
                    ob["transport"]["headers"] = {"Host": n["wsHeaders"]["Host"]}
            elif net and net != "tcp":
                ob["transport"] = {"type": net}
            if n.get("tls") == "tls":
                sni = n.get("sni", "") or n.get("wsHeaders", {}).get("Host", "") or server
                ob["tls"] = {"enabled": True, "server_name": sni}
            outbounds.append(ob)

        elif ntype == "vless":
            ob = {
                "type": "vless",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": n.get("uuid", ""),
                "flow": n.get("flow", ""),
            }
            net = n.get("network", "")
            if net == "ws":
                ob["transport"] = {"type": "ws", "path": n.get("wsPath", "/")}
                if n.get("wsHeaders", {}).get("Host"):
                    ob["transport"]["headers"] = {"Host": n["wsHeaders"]["Host"]}
            elif net and net != "tcp":
                ob["transport"] = {"type": net}
            if n.get("security") == "tls" or n.get("security") == "reality":
                sni = n.get("sni", "") or n.get("wsHeaders", {}).get("Host", "") or server
                ob["tls"] = {"enabled": True, "server_name": sni}
            outbounds.append(ob)

        elif ntype == "trojan":
            ob = {
                "type": "trojan",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": n.get("password", ""),
            }
            outbounds.append(ob)

        elif ntype == "ss":
            ob = {
                "type": "shadowsocks",
                "tag": tag,
                "server": server,
                "server_port": port,
                "method": n.get("cipher", "aes-256-gcm"),
                "password": n.get("password", ""),
            }
            outbounds.append(ob)

        elif ntype == "hysteria2":
            ob = {
                "type": "hysteria2",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": n.get("password", ""),
            }
            outbounds.append(ob)

        elif ntype == "tuic":
            ob = {
                "type": "tuic",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": n.get("uuid", ""),
                "password": n.get("password", ""),
            }
            outbounds.append(ob)

    return outbounds

def clean_outbound(ob: dict):
    """清理 outbound 中 sing-box 不支持的字段，并智能修复"""
    # 移除 tcp transport（sing-box 默认就是 tcp）
    if "transport" in ob and ob["transport"].get("type") == "tcp":
        del ob["transport"]
    # 移除 network 字段（不是 sing-box 标准字段）
    ob.pop("network", None)
    # 移除空的 transport
    if "transport" in ob and not ob["transport"]:
        del ob["transport"]
    # 移除废弃的 dns outbound（1.13.0+ 不支持）
    if ob.get("type") == "dns":
        return None  # 返回 None 表示需要过滤掉
    # 移除 security/alter_id 等 sing-box 不支持的字段
    ob.pop("security", None)
    ob.pop("alter_id", None)
    ob.pop("alterId", None)
    # 智能修复：自动添加 tls
    tag = ob.get("tag", "")
    port = ob.get("server_port", ob.get("port", 0))
    otype = ob.get("type", "")
    if "tls" not in ob:
        # 确定 sni/server_name
        sni = ob.get("sni", "")
        if not sni:
            transport = ob.get("transport", {})
            sni = transport.get("headers", {}).get("Host", "")
        if not sni:
            sni = ob.get("server", "")
        if otype in ("hysteria2", "tuic"):
            ob["tls"] = {"enabled": True, "server_name": sni}
        elif otype in ("vless", "vmess", "trojan"):
            if "TLS" in tag.upper() or port == 443:
                ob["tls"] = {"enabled": True, "server_name": sni}
    # 修复空 password/uuid
    if otype in ("hysteria2", "tuic"):
        if not ob.get("password", "").strip():
            ob["password"] = "placeholder"
        if otype == "tuic" and not ob.get("uuid", "").strip():
            ob["uuid"] = "00000000-0000-0000-0000-000000000000"
    return ob

def build_singbox_config(nodes: list[dict], config_name: str = "") -> dict:
    """构建完整的 sing-box config.json。
    如果节点已经是完整的 sing-box outbound 格式（有 server 和 server_port），直接使用。
    """
    # 检查节点是否已经是完整的 sing-box 格式
    if nodes and all(
        n.get("server") and n.get("server_port") and n.get("type") in (
            "vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic"
        ) for n in nodes
    ):
        # 直接使用，只清理不支持的字段
        outbounds = []
        for n in nodes:
            ob = dict(n)  # 复制
            ob["tag"] = ob.get("tag", ob.get("name", "unknown"))
            if clean_outbound(ob) is not None:
                outbounds.append(ob)
    else:
        outbounds = nodes_to_singbox_outbounds(nodes)
        outbounds = [ob for ob in outbounds if clean_outbound(ob) is not None]

    # 地区分组
    groups = {}
    for o in outbounds:
        tag = o["tag"]
        server = o.get("server", "")
        region = get_region(tag, server)
        if region:
            groups.setdefault(region, []).append(tag)

    region_selectors = []
    for region, tags in sorted(groups.items()):
        region_selectors.append({
            "type": "urltest",
            "tag": region,
            "outbounds": tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "5m",
        })

    # 全部
    all_outbounds = list(node_tags) + [r["tag"] for r in region_selectors]
    all_selector = {
        "type": "selector",
        "tag": "全部",
        "outbounds": all_outbounds,
    }

    # Proxy
    proxy_outbounds = ["全部"] + [r["tag"] for r in region_selectors]
    proxy_selector = {
        "type": "selector",
        "tag": "Proxy",
        "outbounds": proxy_outbounds,
    }

    # 筛选规则
    rule_selectors = []
    for rule_name in ["Youtube", "Telegram", "Github", "Openai", "Netflix", "Google"]:
        rule_selectors.append({
            "type": "selector",
            "tag": rule_name,
            "outbounds": ["Proxy", "全部"] + [r["tag"] for r in region_selectors],
        })

    config = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "dns-remote", "address": "tls://1.1.1.1", "detour": "Proxy"},
                {"tag": "dns-local", "address": "udp://223.5.5.5", "detour": "direct"},
                {"tag": "dns-fakeip", "address": "fakeip"},
            ],
            "rules": [
                {"domain_suffix": ["cn"], "server": "dns-local"},
                {"rule_set": ["cnip"], "server": "dns-local"},
                {"query_type": ["A", "AAAA"], "server": "dns-fakeip"},
            ],
            "final": "dns-remote",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"},
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "0.0.0.0",
                "listen_port": 2080,
            },
            {
                "type": "tproxy",
                "tag": "tproxy-in",
                "listen": "::",
                "listen_port": 9888,
            },

        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            proxy_selector,
            *rule_selectors,
            *outbounds,
            *region_selectors,
            all_selector,
        ],
        "route": {
            "auto_detect_interface": True,
            "rule_set": [
                {
                    "type": "local",
                    "tag": "cnip",
                    "format": "binary",
                    "path": "cn.srs",
                },
            ],
            "rules": [
                {"protocol": "dns", "outbound": "direct"},
                {"rule_set": ["cnip"], "outbound": "direct"},
                {"domain_suffix": ["cn"], "outbound": "direct"},
                {"outbound": "Proxy"},
            ],
            "final": "Proxy",
        },
        "experimental": {
            "cache_file": {"enabled": True, "path": "/root/singbox/cache.db"},
        },
    }
    return config

def fix_config(config: dict) -> dict:
    """修复配置中的常见问题"""
    # 修复 UUID 中的 %3A 编码
    for o in config.get("outbounds", []):
        uuid_val = o.get("uuid", "")
        if "%3A" in uuid_val or "%3a" in uuid_val:
            o["uuid"] = uuid_val.split("%3A")[0].split("%3a")[0]
    # 修复 rule_set URL
    for rs in config.get("route", {}).get("rule_set", []):
        if "url" in rs:
            rs["url"] = rs["url"].replace("https://mirror.ghproxy.com/", "")
            rs["url"] = rs["url"].replace("https://wiki.jokin.uk/cnip2.srs",
                "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs")
    # 不修改 clash_api 端口，保持前端配置

    # 自动地区分组：从 outbounds 中提取节点并生成地区 selector
    node_tags = []
    node_servers = {}
    for o in config.get("outbounds", []):
        if o.get("type") in ("vless", "vmess", "trojan", "shadowsocks", "hysteria2"):
            tag = o.get("tag", "")
            node_tags.append(tag)
            node_servers[tag] = o.get("server", "")

    if node_tags:
        groups = {}
        for tag in node_tags:
            region = get_region(tag, node_servers.get(tag, ""))
            if region:
                groups.setdefault(region, []).append(tag)

        region_selectors = []
        for region, tags in sorted(groups.items()):
            region_selectors.append({
                "type": "urltest",
                "tag": region,
                "outbounds": tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m",
            })

        # 重建 outbounds：direct, block, Proxy, 规则, 节点, 地区, 全部
        new_outbounds = []
        for o in config.get("outbounds", []):
            if o.get("type") in ("direct", "block"):
                new_outbounds.append(o)
            elif o.get("tag") in ("Proxy",):
                # 更新 Proxy 的 outbounds
                o["outbounds"] = ["全部"] + [r["tag"] for r in region_selectors]
                new_outbounds.append(o)
            elif o.get("tag") in ("Youtube", "Telegram", "Github", "Openai", "Netflix", "Google"):
                o["outbounds"] = ["Proxy", "全部"] + [r["tag"] for r in region_selectors]
                new_outbounds.append(o)

        # 添加节点
        for o in config.get("outbounds", []):
            if o.get("type") in ("vless", "vmess", "trojan", "shadowsocks", "hysteria2"):
                new_outbounds.append(o)

        # 添加地区分组
        new_outbounds.extend(region_selectors)

        # 添加/更新 全部
        all_outbounds = list(node_tags) + [r["tag"] for r in region_selectors]
        all_found = False
        for o in new_outbounds:
            if o.get("tag") == "全部":
                o["outbounds"] = all_outbounds
                all_found = True
                break
        if not all_found:
            new_outbounds.append({"type": "selector", "tag": "全部", "outbounds": all_outbounds})

        config["outbounds"] = new_outbounds

    return config

# ============ API 路由 ============

@app.get("/api/subscriptions")
async def list_subscriptions():
    """列出所有订阅"""
    subs = []
    for f in SUBS_DIR.glob("*.json"):
        with open(f) as fp:
            data = json.load(fp)
            subs.append({"name": data["name"], "url": data["url"], "nodes_count": len(data.get("nodes", []))})
    return {"code": 0, "data": subs}

@app.post("/api/subscriptions")
async def create_subscription(sub: SubCreate):
    """创建订阅"""
    # 获取订阅内容
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(sub.url, headers={"User-Agent": "sbtool-server/1.0"})
            text = resp.text
        except Exception as e:
            raise HTTPException(400, f"获取订阅失败: {e}")

    # 解析节点
    nodes = []
    if sub.url.endswith(".yaml") or sub.url.endswith(".yml") or "proxies:" in text[:500]:
        nodes = parse_clash_subscription(text)
    if not nodes:
        nodes = parse_v2ray_subscription(text)

    if not nodes:
        raise HTTPException(400, "未能解析到任何节点")

    # 给节点打上地区标签
    for n in nodes:
        region = get_region(n.get("name", ""))
        if region:
            n["region"] = region

    # 保存
    sub_file = SUBS_DIR / f"{sub.name}.json"
    sub_data = {"name": sub.name, "url": sub.url, "nodes": nodes, "created_at": time.time()}
    with open(sub_file, "w") as f:
        json.dump(sub_data, f, ensure_ascii=False, indent=2)

    return {"code": 0, "message": f"订阅创建成功，共 {len(nodes)} 个节点", "nodes_count": len(nodes)}

@app.delete("/api/subscriptions/{name}")
async def delete_subscription(name: str):
    sub_file = SUBS_DIR / f"{name}.json"
    if sub_file.exists():
        sub_file.unlink()
        return {"code": 0, "message": "删除成功"}
    raise HTTPException(404, "订阅不存在")

@app.get("/api/subscriptions/{name}/nodes")
async def get_subscription_nodes(name: str):
    """获取订阅节点"""
    sub_file = SUBS_DIR / f"{name}.json"
    if not sub_file.exists():
        raise HTTPException(404, "订阅不存在")
    with open(sub_file) as f:
        data = json.load(f)
    nodes = data.get("nodes", [])
    # 统计地区并给节点名加地区前缀
    regions = {}
    for n in nodes:
        r = get_region(n.get("name", ""))
        if r:
            regions[r] = regions.get(r, 0) + 1
            if not n.get("region"):
                n["region"] = r
    return {"code": 0, "data": {"nodes": nodes, "regions": regions, "total": len(nodes)}}

@app.post("/api/generate")
async def generate_config(data: ConfigData):
    """生成 sing-box 配置"""
    sub_file = SUBS_DIR / f"{data.name}.json"
    if not sub_file.exists():
        raise HTTPException(404, "订阅不存在")
    with open(sub_file) as f:
        sub_data = json.load(f)

    config = build_singbox_config(sub_data["nodes"], data.name)
    config = fix_config(config)

    # 保存配置
    config_file = CONFIGS_DIR / f"{data.name}.json"
    with open(config_file, "w") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    return {"code": 0, "message": "配置生成成功", "config": config}

@app.get("/api/configs")
async def list_configs():
    """列出所有配置"""
    configs = []
    for f in CONFIGS_DIR.glob("*.json"):
        configs.append({"name": f.stem, "size": f.stat().st_size})
    return {"code": 0, "data": configs}

@app.get("/api/configs/{name}")
async def get_config(name: str):
    config_file = CONFIGS_DIR / f"{name}.json"
    if not config_file.exists():
        raise HTTPException(404, "配置不存在")
    with open(config_file) as f:
        return {"code": 0, "data": json.load(f)}

@app.post("/api/deploy/{name}")
async def deploy_config(name: str, target: str = Query("local")):
    """部署配置到 sing-box。target=remote 时部署到 101"""
    config_file = CONFIGS_DIR / f"{name}.json"
    if not config_file.exists():
        raise HTTPException(404, "配置不存在")

    with open(config_file) as f:
        config = json.load(f)

    config = fix_config(config)

    tmp_file = "/tmp/singbox_config_deploy.json"
    with open(tmp_file, "w") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    try:
        if target == "remote":
            # 部署到远程机器，通过 base64 传输
            remote_host = os.environ.get("REMOTE_HOST", "192.168.50.101")
            remote_user = os.environ.get("REMOTE_USER", "chuenyu")
            remote_pw = os.environ.get("REMOTE_PW", "")
            if not remote_pw:
                return {"code": 1, "message": "未设置 REMOTE_PW 环境变量"}
            import base64 as b64
            with open(tmp_file, "rb") as f:
                config_b64 = b64.b64encode(f.read()).decode()
            subprocess.run([
                "sshpass", "-p", remote_pw, "ssh", "-o", "StrictHostKeyChecking=no",
                f"{remote_user}@{remote_host}",
                f"echo {remote_pw} | sudo -S python3 -c \"import base64,json; c=json.loads(base64.b64decode('{config_b64}')); json.dump(c, open('/root/singbox/config.json','w'), indent=2, ensure_ascii=False)\" && echo {remote_pw} | sudo -S systemctl restart singbox"
            ], check=True, timeout=30)
            time.sleep(3)
            result = subprocess.run([
                "sshpass", "-p", remote_pw, "ssh", "-o", "StrictHostKeyChecking=no",
                f"{remote_user}@{remote_host}",
                f"echo {remote_pw} | sudo -S systemctl is-active singbox"
            ], capture_output=True, text=True)
            if "active" in result.stdout:
                return {"code": 0, "message": "部署到 101 成功，singbox 已重启"}
            else:
                return {"code": 1, "message": f"配置已写入但 singbox 启动失败: {result.stdout.strip()}"}
        else:
            subprocess.run(["sudo", "mkdir", "-p", str(SINGBOX_CONFIG.parent)], check=True)
            subprocess.run(["sudo", "cp", tmp_file, str(SINGBOX_CONFIG)], check=True)
            subprocess.run(["sudo", "systemctl", "restart", "singbox"], check=True, timeout=30)
            time.sleep(3)
            result = subprocess.run(["sudo", "systemctl", "is-active", "singbox"], capture_output=True, text=True)
            if "active" in result.stdout:
                return {"code": 0, "message": "部署成功，singbox 已重启"}
            else:
                return {"code": 1, "message": "配置已写入但 singbox 启动失败，请检查日志"}
    except Exception as e:
        return {"code": 1, "message": f"部署失败: {e}"}

@app.get("/api/status")
async def singbox_status():
    """获取 singbox 状态"""
    try:
        result = subprocess.run(["sudo", "systemctl", "is-active", "singbox"], capture_output=True, text=True)
        status = result.stdout.strip()
        ports = {}
        ss_result = subprocess.run(["sudo", "ss", "-tlnp"], capture_output=True, text=True)
        for line in ss_result.stdout.split("\n"):
            if "9090" in line:
                ports["yacd"] = 9090
            if "2080" in line:
                ports["mixed"] = 2080
        return {"code": 0, "data": {"status": status, "ports": ports}}
    except Exception as e:
        return {"code": 1, "message": str(e)}

@app.get("/api/restart")
async def restart_singbox():
    """重启 singbox"""
    try:
        subprocess.run(["sudo", "systemctl", "restart", "singbox"], check=True, timeout=10)
        time.sleep(2)
        result = subprocess.run(["sudo", "systemctl", "is-active", "singbox"], capture_output=True, text=True)
        return {"code": 0, "message": f"singbox 状态: {result.stdout.strip()}"}
    except Exception as e:
        return {"code": 1, "message": str(e)}

@app.get("/api/upgrade")
async def upgrade_singbox():
    """升级 sing-box"""
    try:
        # 获取最新版本
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=5",
                headers={"User-Agent": "sbtool-server"}
            )
            releases = resp.json()
            if not releases:
                return {"code": 1, "message": "获取版本信息失败"}
            latest = releases[0]
            version = latest["tag_name"].lstrip("v")

        # 下载（本机透明代理）
        arch = "amd64"
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-linux-{arch}.tar.gz"
        subprocess.run(["/usr/bin/wget", "-q", url, "-O", "/tmp/sing-box.tar.gz"], check=True, timeout=120)
        subprocess.run(["/usr/bin/tar", "-xzf", "/tmp/sing-box.tar.gz", "-C", "/tmp"], check=True)
        subprocess.run(["/usr/bin/cp", f"/tmp/sing-box-{version}-linux-{arch}/sing-box", "/usr/local/bin/sing-box"], check=True)
        subprocess.run(["/usr/bin/chmod", "+x", "/usr/local/bin/sing-box"], check=True)

        # 重启
        subprocess.run(["systemctl", "restart", "singbox"], check=True, timeout=10)
        time.sleep(2)
        return {"code": 0, "message": f"已升级到 v{version} 并重启"}
    except Exception as e:
        return {"code": 1, "message": str(e)}

# ============ 兼容 sbtool 前端 API ============

@app.post("/createSub")
async def sbtool_create_sub(request: Request):
    """兼容 sbtool 前端: POST /createSub?name=xxx"""
    name = request.query_params.get("name", "default")
    body = await request.json()
    url = body.get("url", "")

    if not url:
        raise HTTPException(400, "缺少订阅 URL")

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(url, headers={"User-Agent": "sbtool-server/1.0"})
            text = resp.text
        except Exception as e:
            return JSONResponse({"code": 1, "message": f"获取订阅失败: {e}"})

    nodes = []
    if "proxies:" in text[:500]:
        nodes = parse_clash_subscription(text)
    if not nodes:
        nodes = parse_v2ray_subscription(text)

    if not nodes:
        return JSONResponse({"code": 1, "message": "未能解析到任何节点"})

    sub_file = SUBS_DIR / f"{name}.json"
    sub_data = {"name": name, "url": url, "nodes": nodes, "created_at": time.time()}
    with open(sub_file, "w") as f:
        json.dump(sub_data, f, ensure_ascii=False, indent=2)

    return {"code": 0, "message": f"订阅创建成功，共 {len(nodes)} 个节点"}

@app.post("/editConfig")
async def sbtool_edit_config(request: Request):
    """兼容 sbtool 前端: POST /editConfig"""
    body = await request.json()
    config = body.get("config", body)

    if not config or not isinstance(config, dict):
        raise HTTPException(400, "无效的配置")

    config = fix_config(config)

    tmp_file = "/tmp/singbox_config_edit.json"
    with open(tmp_file, "w") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    try:
        subprocess.run(["sudo", "mkdir", "-p", str(SINGBOX_CONFIG.parent)], check=True)
        subprocess.run(["sudo", "cp", tmp_file, str(SINGBOX_CONFIG)], check=True)
        subprocess.run(["sudo", "systemctl", "restart", "singbox"], check=True, timeout=10)
        return {"code": 0, "message": "配置文件上传成功"}
    except Exception as e:
        return {"code": 1, "message": f"配置已保存但重启失败: {e}"}

@app.get("/runScript")
async def sbtool_run_script():
    """兼容 sbtool 前端: GET /runScript"""
    try:
        subprocess.run(["sudo", "systemctl", "restart", "singbox"], check=True, timeout=10)
        time.sleep(2)
        result = subprocess.run(["sudo", "systemctl", "is-active", "singbox"], capture_output=True, text=True)
        return {"code": 0, "message": f"singbox 已重启，状态: {result.stdout.strip()}"}
    except Exception as e:
        return {"code": 1, "message": str(e)}

@app.get("/upgradeSingbox")
async def sbtool_upgrade():
    """兼容 sbtool 前端: GET /upgradeSingbox"""
    return await upgrade_singbox()

@app.get("/sub")
async def sbtool_get_sub(name: str = Query("default")):
    """兼容 sbtool 前端: GET /sub?name=xxx"""
    sub_file = SUBS_DIR / f"{name}.json"
    if not sub_file.exists():
        raise HTTPException(404, "订阅不存在")
    with open(sub_file) as f:
        data = json.load(f)
    return {"code": 0, "data": {"name": data["name"], "url": data["url"], "nodes_count": len(data.get("nodes", []))}}

# ============ 静态文件 ============
@app.get("/scg/{path:path}")
async def scg_static(path: str):
    file_path = STATIC_DIR / "scg" / path
    if file_path.is_file():
        return FileResponse(file_path)
    if file_path.is_dir():
        index_path = file_path / "index.html"
        if index_path.is_file():
            return FileResponse(index_path)
    return HTMLResponse("Not Found", status_code=404)

@app.get("/{path:path}")
async def spa_fallback(path: str):
    """SPA fallback"""
    index_path = STATIC_DIR / "scg" / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse("<h1>sbtool-server running</h1>")

@app.get("/")
async def root():
    index_path = STATIC_DIR / "scg" / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse("<h1>sbtool-server running</h1>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
