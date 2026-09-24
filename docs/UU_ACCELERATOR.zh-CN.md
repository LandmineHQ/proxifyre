# UU 加速器兼容处理

[English](UU_ACCELERATOR.md)

## 范围

本文说明 ProxiFyre 实现的 UU 兼容路径，包括涉及的 UU 组件、组件之间传递的
策略值、被修补的函数，以及只修改已加载 `local_proxy.dll` 映像的运行时机制。

UU 的该路径使用 Windows Filtering Platform (WFP)。ProxiFyre 从 WPF 界面应用
兼容补丁，不修改已安装 DLL 的磁盘内容，也不修改其 Authenticode 签名。

## 组件

| 组件 | 职责 |
| --- | --- |
| `uu.exe` | 界面、进程选择、驱动安装和运行时生命周期管理。 |
| `local_proxy.dll` | 加载 UU 策略，选择加速进程和代理端点，并配置 UU WFP 驱动。 |
| `uuwfp.sys` | WFP callout 驱动。拦截选定的 TCP、UDP 和 ICMP 流，并与 `local_proxy.dll` 交换报文或连接状态。 |
| `uunetfilter.sys` | 部分 UU 模式使用的通用 NetFilter2/NF3 重定向路径，不负责域名白名单策略。 |

UU 界面是 32 位进程。加速开始时，`local_proxy.dll` 被加载到 UU 进程。当前
安装目录名和伪造的文件版本不能作为可靠身份标识：多个 UU 版本的
`local_proxy.dll` 都可能报告版本 `9.9.9.99`。

## 运行时数据流

1. `uu.exe` 选择目标应用并启动本地代理运行时。
2. `start_local_proxy` 加载 UU 策略并创建本地策略状态。
3. `local_proxy.dll` 解析进程、域名、IP、端口、协议和路由配置。
4. 每个流首先检查进程 ACL。兼容补丁不会让无关进程变为可加速进程。
5. 进程 ACL 接受该流后，TCP 和 UDP 路径再检查进程域名限制、目标规则、
   封禁列表、浏览器 QUIC 策略和代理选择。
6. `local_proxy.dll` 将选定的运行时值写入
   `HKLM\SYSTEM\CurrentControlSet\Services\uuwfp\Parameters`。
7. 同一模块通过控制 IOCTL 配置 `uuwfp.sys`：

   | IOCTL | 操作 |
   | --- | --- |
   | `0x120004` | 读取排队的驱动报文或 ICMP 事件。 |
   | `0x120008` | 设置驱动信号事件。 |
   | `0x12000C` | 设置远端代理 IP 和端口。 |
   | `0x120010` | 设置驱动使用的 `svchost` 或 DoSvc PID。 |
   | `0x120014` | 读取待处理的 TCP SYN 项。 |
   | `0x120018` | 设置 TCP SYN 信号事件。 |
   | `0x12001C` | 完成或释放 TCP SYN 项。 |

`uuwfp.sys` 接收进程和端点状态，但不接收或解析域名。域名和目标策略判断在
`local_proxy.dll` 中完成，然后再配置驱动。

## 策略变量

兼容补丁保留原有策略对象，只修改拒绝检查的返回值。涉及的主要值如下：

| 值 | 用途 |
| --- | --- |
| `process_domain_restriction` | 控制进程与域名限制路径。被修补的函数对该检查返回中性结果。 |
| `tcp_whitelists` | 本地代理策略使用的 TCP 加速选择条件。 |
| `udp_whitelists` | 本地代理策略使用的 UDP 加速选择条件。 |
| `ip_port_hijack` | 流被选中时使用的目标 IP/端口路由或改写策略。 |
| `proxy_pid` | 已选择的本地代理进程 PID。 |
| `proxy_name` | 与本地代理关联的可执行文件或进程名。 |
| `proxy_ip` | 传递给 `uuwfp.sys` 的远端代理地址。 |
| `proxy_port` | 传递给 `uuwfp.sys` 的远端代理端口。 |
| `u_on` | 通过服务参数写入的本地代理启用状态。 |
| `i_on` | 通过服务参数写入的 IP 流启用状态。 |
| `t_s_on` | 通过服务参数写入的 TCP SYN 处理状态。 |

这些值仍由 UU 管理。ProxiFyre 不写入这些值，也不会用固定值替换它们。

## 被修补的函数

补丁目标为 `local_proxy.dll` 中的七个策略函数。下表中的名称是 ProxiFyre
使用的稳定诊断标识，不是 DLL 导出符号。它们描述各目标的调用方可见契约：

| 函数 | 当前 RVA | 修补后返回 | 调用方可见效果 |
| --- | ---: | --- | --- |
| `UuPatch_DisableTcpProcessDomainRestriction` | `0x526C0` | `false`，callee cleanup `8` | TCP 路径报告无进程域名限制。 |
| `UuPatch_DisableUdpProcessDomainRestriction` | `0xB2A10` | `false`，callee cleanup `16` | UDP 路径报告无进程域名限制。 |
| `UuPatch_TreatEveryDestinationAsProxyAclMatch` | `0x996A0` | `true`，callee cleanup `12` | 已通过进程选择的目标都被视为 ACL 匹配。 |
| `UuPatch_DisableTcpDestinationBanList` | `0x9A770` | `false`，callee cleanup `4` | TCP 目标不再被目标封禁列表拒绝。 |
| `UuPatch_DisableUdpGameBanList` | `0x9A870` | `false`，callee cleanup `4` | UDP 游戏目标不再被游戏封禁列表拒绝。 |
| `UuPatch_DisableBrowserQuicBlock` | `0x994B0` | `false`，callee cleanup `12` | 浏览器 QUIC 报文不再被该策略检查阻止。 |
| `UuPatch_DisableUdpDestinationPortBlockRules` | `0x9DC80` | `false`，callee cleanup `4` | UDP 目标和端口封锁规则不再拒绝该流。 |

替换字节如下：

| 函数 | 原始前缀 | 替换字节 |
| --- | --- | --- |
| TCP 进程域名限制 | `55 8B EC 6A FF` | `32 C0 C2 08 00` |
| UDP 进程域名限制 | `55 8B EC 6A FF` | `32 C0 C2 10 00` |
| 代理 ACL 目标匹配 | `55 8B EC 6A FF` | `B0 01 C2 0C 00` |
| TCP 目标封禁列表 | `55 8B EC 83 EC` | `32 C0 C2 04 00` |
| UDP 游戏封禁列表 | `55 8B EC 83 EC` | `32 C0 C2 04 00` |
| 浏览器 QUIC 阻止 | `55 8B EC 6A FF` | `32 C0 C2 0C 00` |
| UDP 目标/端口封锁规则 | `55 8B EC 83 EC` | `32 C0 C2 04 00` |

这些桩代码沿用目标函数自身的返回约定：

- `32 C0` 是 `xor al, al`，返回 `false`。
- `B0 01` 是 `mov al, 1`，返回 `true`。
- `C2 imm16` 是保留原参数清理宽度的 callee cleanup 返回。

每个替换都恰好为五字节，只替换原始五字节前缀。函数其余字节仍保留在内存中，
但不会被执行。

## 补丁配置

补丁配置保存在 `src/Shared/UuPatchProfiles.json`。当前维护的 profile 为
`uu-5247`，其标签记录 UU `6.18.3` 和本地代理版本 `9.9.9.99`。该签名族
同样兼容 `5248` 的函数体，两者解析到相同的七个目标 RVA。

每个 profile 包含：

| 字段 | 含义 |
| --- | --- |
| `key` | 用于诊断和离线补丁脚本的稳定 profile 标识。 |
| `label` | 供人阅读的版本描述。 |
| `version` | 仅作元数据，不用于判断兼容性。 |
| `sha256` | 受支持原始 `local_proxy.dll` 的精确哈希。 |
| `patchedSha256` | 对应离线补丁 DLL 的精确哈希。 |
| `targets` | 此 profile 要修改的函数列表。 |

每个目标包含：

| 字段 | 含义 |
| --- | --- |
| `name` | 描述策略检查的诊断名称。 |
| `rva` | 仅在源文件哈希与 profile 精确匹配时使用的固定偏移。 |
| `signature` | 唯一可执行代码模式，使用 `??` 通配重定位敏感字节。 |
| `signatureOffset` | 从签名匹配位置到首个修改字节的偏移。当前目标均为 `0`。 |
| `original` | 补丁前的预期字节。 |
| `patched` | 写入相同地址的替换字节。 |

当前签名会通配绝对地址和相对调用目标。因此，即使 DLL 的其他部分布局发生
变化，只要能唯一找到这些目标函数，就不需要猜测新地址。

## 函数定位

定位器读取 PE 映像，并且只扫描可执行节。

1. 计算 `local_proxy.dll` 的 SHA256。
2. 如果哈希精确匹配 `sha256` 或 `patchedSha256`，选择该 profile。优先使用
   签名定位；只有该精确映像可以使用配置中的 RVA 作为回退。
3. 如果哈希未知，则在没有 RVA 回退的条件下检查每个完整 profile。每个目标
   签名必须在可执行节中恰好匹配一次。
4. 如果多个 profile 同时匹配，则拒绝。
5. 验证每个解析地址包含已知原始字节或已知补丁字节。
6. 如果任一目标缺失、匹配不唯一、位于映像外或字节不符合预期，则在写入前
   拒绝整个 profile。

运行时目标地址计算方式为：

```text
模块基址 + 解析得到的 RVA
```

`fileVersion`、产品版本、安装目录和 profile 标签都不能作为兼容性证明。

## 运行时写入流程

`UuRuntimePatcher` 执行内存补丁：

1. 枚举 UU 安装根目录下或进程名匹配 `uu`/`uu_*` 的 UU 进程。
2. 找到已加载的 `local_proxy.dll`，读取模块路径和基址。
3. 对磁盘 PE 映像解析并验证完整 profile。
4. 读取运行时目标字节，将每个函数分类为原始或已补丁状态。
5. 执行 `Apply` 时暂停目标进程，并在修改任何字节前重新验证全部目标。
6. 将目标页权限改为 `PAGE_EXECUTE_READWRITE`。
7. 通过 `WriteProcessMemory` 写入替换字节。
8. 使用 `FlushInstructionCache` 刷新指令缓存。
9. 恢复原页权限。
10. 恢复进程运行。如果写入失败，则回滚本次操作已经完成的写入。

`Restore` 使用相同流程反向操作，将已知补丁字节恢复为保存的原始字节。已安装
DLL 永远不会以写入方式打开。

## 界面监控

Settings 页通过 `app-config.json` 中的 `enableUuWhitelistPatch` 控制 UU
运行时补丁。

- 界面会报告 `local_proxy.dll` 的状态：原始、部分修补或完全修补。
- 打开开关并确认后应用补丁。
- 关闭开关后恢复运行时进程中的原始字节。
- 开关启用期间，每三秒检查一次 UU；UU 重启或重新加载 `local_proxy.dll`
  后自动重新应用补丁。
- 如果 UU 已提升权限而 ProxiFyre 没有，则在检查或修改 UU 内存前通过
  `runas` 请求提升权限。
- ProxiFyre 正常关闭且当前界面会话应用过补丁时，退出前恢复原始字节。

同一 Settings 页还提供 `detailed` 日志开关。该开关默认关闭，并可在不重启
中继的情况下应用。

## 离线补丁脚本

`scripts/patch-uu-whitelist.ps1` 可以创建或安装用于诊断的磁盘补丁副本。它
使用与运行时补丁器相同的 profile、精确哈希路径和动态签名定位。

正常 WPF 运行时路径不使用离线脚本，也不会替换已安装 DLL。

## 限制

- 兼容版本必须保留全部七个目标签名，并且字节应为已知原始或补丁状态。
- 函数体发生变化时，必须新增或更新 profile。
- 签名必须在可执行节中恰好匹配一次。
- 进程 ACL 验证始终是必要条件。
- Localhost、私有地址、广播、组播、不支持协议、无可用代理线路以及区域/健康
  回退路径不在该补丁范围内。
- 运行时补丁需要访问 UU 进程。受保护进程或已提升权限的 UU 可能要求
  ProxiFyre 同样以管理员权限运行。
- 重启 UU 会丢失内存中的补丁。已安装 DLL 保持不变。
