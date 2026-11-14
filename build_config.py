#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Free-node collector -> mihomo (Clash.Meta) config builder.

Steps: read subs/*.txt (plain or base64) -> parse URIs -> dedupe ->
TCP pre-filter (thread pool) -> emit config.yaml for mihomo.
"""
import base64
import glob
import json
import os
import re
import socket
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
SUBS = os.path.join(HERE, "subs")
DATA = os.path.join(HERE, "data")
OUT = os.path.join(DATA, "config.yaml")
TCP_WORKERS = 200
TCP_TIMEOUT = 2.2
MAX_KEEP = 220

# files in subs/ that are lists of subscription sources, not subscription payloads
SKIP_NAMES = {"sources.txt", "sources.example.txt"}

BAD_HOST_RE = re.compile(r"^(0\.0\.0\.0|127\.|localhost|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1?$)")


# ---------------------------------------------------------------- loading
def load_uris():
    uris = []
    for p in sorted(glob.glob(os.path.join(SUBS, "*.txt"))):
        if os.path.basename(p) in SKIP_NAMES:
            continue
        raw = open(p, "r", encoding="utf-8", errors="ignore").read()
        if not raw.strip() or raw.strip().lower().startswith("404"):
            continue
        text = raw
        if "://" not in raw[:200]:
            compact = re.sub(r"\s+", "", raw)
            try:
                dec = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", "ignore")
                if "://" in dec:
                    text = dec
            except Exception:
                pass
        for line in text.splitlines():
            line = line.strip()
            if "://" in line and not line.startswith("//"):
                uris.append(line)
    return uris


# ---------------------------------------------------------------- helpers
def b64d(s):
    s = s.strip()
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


def qs(sp):
    return urllib.parse.parse_qs(sp.query, keep_blank_values=True)


def g(q, key, default=""):
    v = q.get(key, [default])
    return (v[0] if v else default) or default


def clean_name(n, fallback):
    n = re.sub(r"[\r\n\t]", " ", str(n or "")).strip()
    n = re.sub(r"\s+", " ", n)
    return n or fallback


def add_transport(p, net, host, path, service_name=None):
    net = (net or "tcp").lower()
    if net in ("ws", "websocket"):
        p["network"] = "ws"
        opts = {"path": path or "/"}
        if host:
            opts["headers"] = {"Host": host}
        p["ws-opts"] = opts
    elif net in ("grpc", "gun"):
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": service_name or path or ""}
    elif net in ("h2", "http"):
        p["network"] = "h2"
        opts = {"path": path or "/"}
        if host:
            opts["host"] = [host]
        p["h2-opts"] = opts
    elif net in ("httpupgrade", "http-upgrade"):
        p["network"] = "ws"
        o = {"path": path or "/"}
        if host:
            o["headers"] = {"Host": host}
        p["ws-opts"] = o
    else:
        p["network"] = "tcp"
    return p


# ---------------------------------------------------------------- parsers
def parse_vmess(u):
    body = u[8:].split("#")[0].strip()
    try:
        d = json.loads(b64d(body))
    except Exception:
        return None
    server = str(d.get("add") or "").strip()
    uuid = str(d.get("id") or "").strip()
    try:
        port = int(str(d.get("port") or "0").strip())
    except Exception:
        return None
    if not server or not uuid or not port:
        return None
    net = str(d.get("net") or "tcp").lower()
    tls = str(d.get("tls") or "").lower()
    host = str(d.get("host") or "").strip()
    path = str(d.get("path") or "").strip()
    sni = str(d.get("sni") or host or server).strip()
    try:
        aid = int(str(d.get("aid") or 0))
    except Exception:
        aid = 0
    p = {
        "name": clean_name(d.get("ps"), server),
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": aid,
        "cipher": "auto",
        "udp": True,
    }
    if tls in ("tls", "reality", "xtls"):
        p["tls"] = True
        p["servername"] = sni
        p["skip-cert-verify"] = True
    if str(d.get("fp") or ""):
        p["client-fingerprint"] = str(d.get("fp"))
    return add_transport(p, net, host, path)


def parse_vless(u):
    sp = urllib.parse.urlsplit(u)
    q = qs(sp)
    server, port, uuid = sp.hostname, sp.port, sp.username
    if not server or not port or not uuid:
        return None
    sec = g(q, "security", "none").lower()
    net = g(q, "type", "tcp")
    sni = g(q, "sni") or g(q, "host") or server
    p = {
        "name": clean_name(urllib.parse.unquote(sp.fragment), f"{server}:{port}"),
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "udp": True,
    }
    if g(q, "flow"):
        p["flow"] = g(q, "flow")
    if sec in ("tls", "xtls", "reality"):
        p["tls"] = True
        p["servername"] = sni
        p["skip-cert-verify"] = True
    if sec == "reality":
        pbk, sid = g(q, "pbk"), g(q, "sid")
        if pbk:
            ro = {"public-key": pbk}
            if sid:
                ro["short-id"] = sid
            p["reality-opts"] = ro
    if g(q, "fp"):
        p["client-fingerprint"] = g(q, "fp")
    return add_transport(p, net, g(q, "host"), g(q, "path"), g(q, "serviceName"))


def parse_ss(u):
    body = u[5:]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    frag = urllib.parse.unquote(frag)
    if "?" in body:
        body = body.split("?", 1)[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            try:
                userinfo = b64d(userinfo)
            except Exception:
                return None
        method, _, password = userinfo.partition(":")
    else:
        try:
            dec = b64d(body)
        except Exception:
            return None
        if "@" not in dec:
            return None
        userinfo, hostport = dec.rsplit("@", 1)
        method, _, password = userinfo.partition(":")
    if ":" not in hostport:
        return None
    server, _, port_s = hostport.rpartition(":")
    try:
        port = int(port_s)
    except Exception:
        return None
    if not server or not method or not port:
        return None
    return {
        "name": clean_name(frag, f"{server}:{port}"),
        "type": "ss",
        "server": server.strip("[]"),
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True,
    }


def parse_trojan(u):
    sp = urllib.parse.urlsplit(u)
    q = qs(sp)
    if not sp.hostname or not sp.port or not sp.username:
        return None
    p = {
        "name": clean_name(urllib.parse.unquote(sp.fragment), f"{sp.hostname}:{sp.port}"),
        "type": "trojan",
        "server": sp.hostname,
        "port": sp.port,
        "password": urllib.parse.unquote(sp.username),
        "udp": True,
        "skip-cert-verify": True,
    }
    sni = g(q, "sni") or g(q, "peer")
    if sni:
        p["sni"] = sni
    if g(q, "type"):
        add_transport(p, g(q, "type"), g(q, "host"), g(q, "path"), g(q, "serviceName"))
    return p


def parse_hysteria2(u):
    sp = urllib.parse.urlsplit(u)
    q = qs(sp)
    if not sp.hostname or not sp.port:
        return None
    pwd = urllib.parse.unquote(sp.username or "")
    if sp.password:
        pwd += ":" + urllib.parse.unquote(sp.password)
    p = {
        "name": clean_name(urllib.parse.unquote(sp.fragment), f"{sp.hostname}:{sp.port}"),
        "type": "hysteria2",
        "server": sp.hostname,
        "port": sp.port,
        "password": pwd or g(q, "auth"),
        "udp": True,
        "skip-cert-verify": True,
    }
    sni = g(q, "sni") or g(q, "peer")
    if sni:
        p["sni"] = sni
    if g(q, "obfs"):
        p["obfs"] = g(q, "obfs")
        p["obfs-password"] = g(q, "obfs-password")
    return p


def parse_hysteria(u):
    sp = urllib.parse.urlsplit(u)
    q = qs(sp)
    if not sp.hostname or not sp.port:
        return None
    p = {
        "name": clean_name(urllib.parse.unquote(sp.fragment), f"{sp.hostname}:{sp.port}"),
        "type": "hysteria",
        "server": sp.hostname,
        "port": sp.port,
        "protocol": g(q, "protocol", "udp"),
        "up": g(q, "upmbps", "50"),
        "down": g(q, "downmbps", "100"),
        "skip-cert-verify": True,
    }
    if g(q, "auth"):
        p["auth-str"] = g(q, "auth")
    if g(q, "peer"):
        p["sni"] = g(q, "peer")
    return p


def parse_tuic(u):
    sp = urllib.parse.urlsplit(u)
    q = qs(sp)
    if not sp.hostname or not sp.port or not sp.username:
        return None
    p = {
        "name": clean_name(urllib.parse.unquote(sp.fragment), f"{sp.hostname}:{sp.port}"),
        "type": "tuic",
        "server": sp.hostname,
        "port": sp.port,
        "uuid": urllib.parse.unquote(sp.username),
        "password": urllib.parse.unquote(sp.password or ""),
        "udp": True,
        "skip-cert-verify": True,
    }
    if g(q, "sni"):
        p["sni"] = g(q, "sni")
    if g(q, "congestion_control"):
        p["congestion-controller"] = g(q, "congestion_control")
    return p


PARSERS = {
    "vmess": parse_vmess,
    "vless": parse_vless,
    "ss": parse_ss,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "hysteria": parse_hysteria,
    "tuic": parse_tuic,
}


def parse_uri(u):
    scheme = u.split("://", 1)[0].lower()
    fn = PARSERS.get(scheme)
    if not fn:
        return None
    try:
        p = fn(u)
    except Exception:
        return None
    if not p:
        return None
    srv = str(p.get("server", ""))
    if not srv or BAD_HOST_RE.match(srv) or srv in ("0.0.0.0", "::"):
        return None
    if not (0 < int(p.get("port", 0)) < 65536):
        return None
    return p


# ---------------------------------------------------------------- filter
def tcp_ok(args):
    server, port, idx = args
    try:
        with socket.create_connection((server, port), timeout=TCP_TIMEOUT):
            return idx
    except Exception:
        return None


# ---------------------------------------------------------------- yaml
def sc(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(str(v), ensure_ascii=False)


def dump_map(d, indent):
    sp = "  " * indent
    out = []
    for k, v in d.items():
        if isinstance(v, dict) and v:
            out.append(f"{sp}{k}:")
            out.append(dump_map(v, indent + 1))
        elif isinstance(v, list) and v:
            out.append(f"{sp}{k}:")
            out.append(dump_list(v, indent + 1))
        elif isinstance(v, dict):
            out.append(f"{sp}{k}: {{}}")
        elif isinstance(v, list):
            out.append(f"{sp}{k}: []")
        else:
            out.append(f"{sp}{k}: {sc(v)}")
    return "\n".join(out)


def dump_list(items, indent):
    sp = "  " * indent
    lines = []
    for it in items:
        if isinstance(it, dict):
            first = True
            for k, v in it.items():
                prefix = sp + ("- " if first else "  ")
                first = False
                if isinstance(v, dict) and v:
                    lines.append(f"{prefix}{k}:")
                    lines.append(dump_map(v, indent + 2))
                elif isinstance(v, list) and v:
                    lines.append(f"{prefix}{k}:")
                    lines.append(dump_list(v, indent + 2))
                elif isinstance(v, dict):
                    lines.append(f"{prefix}{k}: {{}}")
                elif isinstance(v, list):
                    lines.append(f"{prefix}{k}: []")
                else:
                    lines.append(f"{prefix}{k}: {sc(v)}")
        else:
            lines.append(f"{sp}- {sc(it)}")
    return "\n".join(lines)


# ---------------------------------------------------------------- main
def main():
    uris = load_uris()
    print(f"[1] raw uris: {len(uris)}")

    proxies, seen = [], set()
    for u in uris:
        p = parse_uri(u)
        if not p:
            continue
        key = (p["type"], p["server"].lower(), p["port"],
               p.get("uuid") or p.get("password") or "")
        if key in seen:
            continue
        seen.add(key)
        proxies.append(p)
    print(f"[2] parsed unique: {len(proxies)}")
    if not proxies:
        print("no proxies parsed")
        return 1

    # TCP pre-filter
    jobs = [(p["server"], p["port"], i) for i, p in enumerate(proxies)]
    alive = []
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        futs = [ex.submit(tcp_ok, j) for j in jobs]
        for f in as_completed(futs):
            r = f.result()
            if r is not None:
                alive.append(r)
    alive.sort()
    print(f"[3] tcp-alive: {len(alive)} / {len(proxies)}")
    if not alive:
        print("nothing alive -> free nodes are dead right now")
        return 2

    keep = [proxies[i] for i in alive][:MAX_KEEP]

    # unique names
    used, final = set(), []
    for i, p in enumerate(keep):
        base = clean_name(p.get("name"), f"{p['type']}-{i+1}")
        name, n = base, 1
        while name in used:
            n += 1
            name = f"{base} #{n}"
        used.add(name)
        p = dict(p)
        p["name"] = name
        final.append(p)

    names = [p["name"] for p in final]
    print(f"[4] kept: {len(final)}")

    has_geo = os.path.exists(os.path.join(DATA, "geosite.dat")) and \
        os.path.exists(os.path.join(DATA, "Country.mmdb"))

    rules = []
    if has_geo:
        rules += ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT,no-resolve"]
    rules += [
        "DOMAIN-SUFFIX,cn,DIRECT",
        "DOMAIN-KEYWORD,-cn,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "MATCH,手动切换",
    ]

    cfg = {
        "mixed-port": 7891,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "external-controller": "127.0.0.1:9090",
        "unified-delay": True,
        "tcp-concurrent": True,
        "geodata-mode": False,
        "geo-auto-update": False,
        "profile": {"store-selected": True, "store-fake-ip": False},
    }

    body = ["proxies:"]
    body.append(dump_list(final, 1))
    body.append("proxy-groups:")
    body.append(dump_list([
        {
            "name": "自动选择",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 180,
            "tolerance": 40,
            "lazy": False,
            "proxies": names,
        },
        {
            "name": "手动切换",
            "type": "select",
            "proxies": ["自动选择"] + names,
        },
    ], 1))
    body.append("rules:")
    body.append(dump_list(rules, 1))

    head = dump_map(cfg, 0)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(head + "\n" + "\n".join(body) + "\n")
    print(f"[5] wrote {OUT}  ({os.path.getsize(OUT)} bytes)")
    print(f"[6] geo data present: {has_geo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

