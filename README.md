# vpn-toolkit

Windows PowerShell 脚本 + 一个 Python 构建器：把若干「订阅文本」解析成一份
[mihomo](https://github.com/MetaCubeX/mihomo)（Clash.Meta）可用的 `config.yaml`，
并提供开关本机系统代理的命令行入口。

仓库里**不含任何节点、订阅地址或内核二进制**——你喂它什么，它就用什么。

## 目录

```
vpn-toolkit/
├── build_config.py      # 订阅文本 -> config.yaml（解析 / 去重 / TCP 预筛 / 生成分组与规则）
├── vpn-refresh.ps1      # 按 subs/sources.txt 抓订阅 -> 重建配置 -> 重启内核
├── vpn-on.ps1           # 启动内核 + 打开 Windows 系统代理（HKCU Internet Settings）
├── vpn-off.ps1          # 停止内核 + 还原系统代理
├── vpn-toggle.ps1       # 看进程状态决定开还是关（给桌面快捷方式用）
└── subs/
    └── sources.example.txt
```

运行期目录（不入库，首次使用自己建）：

```
vpn-toolkit/
├── bin/mihomo.exe           # 自己放：https://github.com/MetaCubeX/mihomo/releases
├── data/config.yaml         # build_config.py 生成的
├── data/Country.mmdb        # GeoIP 库，用作 GEOIP 规则
├── data/geosite.dat         # 域名分类库，用作 GEOSITE 规则
└── subs/*.txt               # 订阅正文 + sources.txt（源清单）
```

## 环境

- Windows 10 / 11，PowerShell 5.1 即可
- Python 3.9+（`build_config.py` 只用标准库）
- `curl.exe`（Win10 1803 起自带）
- mihomo 内核放在 `bin\mihomo.exe`

## 用法

1. 把内核放好，`data\` 里放好 `Country.mmdb` 与 `geosite.dat`。
2. 复制 `subs\sources.example.txt` 为 `subs\sources.txt`，按 `名字 = 地址` 一行一个填你的订阅源；
   以 `mirror = ` 开头的行是可选前置镜像前缀，会依次尝试。
3. 抓订阅并生成配置：

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\vpn-refresh.ps1
   ```

   （也可以只跑 `python build_config.py`，用已经躺在 `subs\` 里的正文重建。）

4. 开 / 关：

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\vpn-on.ps1
   powershell -NoProfile -ExecutionPolicy Bypass -File .\vpn-off.ps1
   ```

   想做成桌面一键开关，给 `vpn-toggle.ps1` 建个快捷方式即可。

## build_config.py 做了什么

1. 读 `subs\*.txt`（跳过 `sources.txt`），自动识别纯文本与 base64
2. 解析 `vmess / vless / ss / trojan / hysteria2 / hy2 / hysteria / tuic`，ssr 跳过
3. 丢弃私网与本机地址，按 `协议+地址+端口+凭据` 去重
4. 线程池做 TCP 连通性预筛（默认 200 并发、2.2 秒超时），只留下真能连上的
5. 生成 `data\config.yaml`：`mixed-port 7891`、`rule` 模式、两个分组
   （`自动选择` = url-test，`手动切换` = select），规则依次是
   `GEOSITE,cn → GEOIP,CN → *.cn → 内网 → MATCH,手动切换`

可调参数都在文件头：`TCP_WORKERS`、`TCP_TIMEOUT`、`MAX_KEEP`、端口、分组名。

## 注意

- 系统代理写在 `HKCU\...\Internet Settings`，只影响当前用户；`vpn-off.ps1` 会把手写的
  `AutoConfigURL` 一并清掉，避免残留一个指向已停服务的 PAC。
- 内核对配置里的节点可用性不做保证：免费节点随时失效，重建一次配置是最省事的刷新方式。
- 订阅内容与节点由使用者自行提供与负责，仓库不携带、也不分发任何节点。
