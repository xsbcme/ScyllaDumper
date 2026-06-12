# ScyllaDumper

Windows x64 内核级进程转存与 PE 修复工具，功能对标 Scylla（Imports Reconstructor）。项目由用户态客户端、内核驱动、驱动加载器和 PE/IAT 重建模块组成，用于在授权的逆向分析、调试研究、软件保护评估和内存取证场景中，从目标进程读取模块映像、搜索并解析 IAT、重建导入表，最终生成更接近可运行状态的 PE 文件。

ScyllaDumper 的核心目标不是简单保存一段内存，而是尽量补齐转存后 PE 常见的关键缺口：节表与文件对齐、入口点、导入地址表、导入描述符以及导入函数名称/序号信息。驱动可选启用；当驱动不可用时，客户端会回退到用户态 API 模式，方便在普通调试场景下继续使用基础转存能力。

> 本项目仅用于你拥有授权的程序分析、兼容性调试、安全研究和取证验证。请勿用于未授权访问、规避第三方防护、破坏服务条款或侵犯他人系统/软件权益的行为。

## 项目作用

- 以内核驱动或用户态 API 读取目标进程内存，支持整块读取和容错式分区域读取。
- 从进程内存或磁盘文件解析 PE 结构，包括 DOS/NT 头、节表、数据目录和 RVA/文件偏移转换。
- 自动搜索 IAT，解析 API 指针对应的模块名、函数名或序号。
- 将解析出的导入信息写回转存文件，重建标准导入表并更新 PE 数据目录。
- 支持模块列表、线程信息、线程上下文、进程基础信息和内存区域查询等辅助分析能力。
- 内置驱动资源，客户端可在管理员权限下尝试加载驱动，也可在驱动不可用时回退到用户态模式。

## 运行环境

- Windows x64。
- Visual Studio 2022，MSVC v143 工具集。
- Windows SDK / WDK 10，用于构建内核驱动项目。
- 管理员权限，用于加载驱动和访问高权限进程。
- 如需加载未签名驱动，需要满足本机测试环境的驱动加载条件。

## 项目结构

```
ScyllaDumper/
├── Common/             通信协议定义
├── DumperDriver/       内核驱动（.sys）
├── DumperClient/       用户态客户端（.exe）
└── DumperLoader/       驱动加载器（kdmapper 封装）
```

---

## DumperClient 功能清单

### 1. 程序入口（`Main.cpp`）

- 支持命令行参数：`--debug` 启用调试日志、直接传入 PID 自动附加目标进程
- 启动时尝试连接内核驱动，连接失败则询问是否加载内置驱动，或自动回退到用户态 API 模式

---

### 2. 通信核心（`DumperClient.cpp / DumperClient.h`）

驱动与用户态的统一抽象接口层，所有 API 根据驱动连接状态自动路由到驱动后端或用户态后端，调用方透明无感知。

| API | 说明 |
|-----|------|
| `Connect()` | 打开命名共享内存 + 同步事件，校验协议版本，建立与驱动的连接 |
| `Disconnect()` | 释放共享内存映射和事件句柄 |
| `Shutdown()` | 发送关闭命令，让驱动工作线程优雅退出并释放内核资源 |
| `OpenProcess(PID)` | 打开目标进程（驱动层直接获取 EPROCESS，绕过用户态访问检查） |
| `CloseProcess()` | 释放目标进程引用 |
| `ReadMemory()` | 从目标进程读取内存（整块读取） |
| `ReadMemoryPartial()` | 分区域读取内存，对未提交页面填零，避免转存中断 |
| `WriteMemory()` | 向目标进程写入内存 |
| `QueryMemory()` | 查询某地址的内存区域信息（状态 / 保护属性 / 类型 / 大小） |
| `ProtectMemory()` | 修改目标进程内存的页面保护属性 |
| `SuspendProcess()` / `ResumeProcess()` | 挂起 / 恢复目标进程（驱动层调用 `PsSuspendProcess`） |
| `EnumModules()` | 枚举目标进程加载的所有模块（基址 / 大小 / 完整路径） |
| `EnumThreads()` | 枚举进程线程（ID / 起始地址 / 状态 / 优先级） |
| `GetThreadContext(TID)` | 获取线程寄存器快照（RAX-R15、RIP、EFLAGS、段寄存器） |
| `GetProcessInfo()` | 获取进程关键信息（PEB 地址、ImageBase、EntryPoint、WoW64、父进程 ID） |
| `EnumProcesses()` | 枚举系统所有进程（无需先 OpenProcess） |

---

### 3. 驱动后端（`DumperClientDriver.cpp`）

实现每条命令向共享内存写入参数 → 触发 `RequestEvent` → 等待 `ResponseEvent` → 读取结果的完整通信流程，包含大数据的自动分块循环传输（单块上限约 4 MB）。

---

### 4. 用户态后端（`DumperClientUser.cpp`）

驱动不可用时的回退实现：

| 功能 | 实现方式 |
|------|---------|
| `OpenProcess` | 尝试高权限，失败回退低权限 |
| `ReadMemory` | 调用 `ReadProcessMemory` |
| `ReadMemoryPartial` | `VirtualQueryEx` 逐区域跳过 `PAGE_GUARD` / `PAGE_NOACCESS` |
| `EnumModules` / `EnumProcesses` | Toolhelp32 API |
| `GetProcessInfo` | `NtQueryInformationProcess` + `IsWow64Process` |

---

### 5. PE 解析器（`PeParser.cpp / PeParser.h`）

| 功能 | 说明 |
|------|------|
| 双源加载 | 支持从进程内存或磁盘文件两种方式解析 PE |
| 头部解析 | DOS 头、NT 头（32/64 位自适应）、节表、数据目录 |
| 节数据读取 | `ReadSectionsFromProcess()`：按 VA / 大小从进程内存读取各节原始数据 |
| 地址转换 | RVA ↔ 文件偏移互转、RVA → 节索引、RVA → 指针 |
| PE 头修复 | 重新对齐节头、修复节偏移（`FixPeHeader` / `AlignAllSectionHeaders`） |
| OEP 设置 | 修改 `AddressOfEntryPoint` 字段 |
| 追加新节 | `AddSection()`：向 PE 追加新节（供导入重建写入 `.SCY` 节） |
| 完整转存 | `DumpProcess()`：读内存 → 修复 PE 头 → 设置 OEP → 写入文件 |

---

### 6. PE 重建（`PeRebuild.cpp / PeRebuild.h`）

- 重新对齐所有节的文件偏移与虚拟地址，使 PE 满足文件对齐规范
- 可选删除 `.reloc` 重定位节（适用于已固定基址的映像）
- 可选更新 PE Checksum

---

### 7. 导入解析器（`ImportResolver.cpp / ImportResolver.h`）

| 功能 | 说明 |
|------|------|
| 导出表缓存 | 从进程内存读取所有已加载 DLL 的导出目录，建立《函数名 / 序号 / RVA》缓存 |
| IAT 解析 | `ReadAndParseIAT()`：逐条读取 IAT 指针，反查模块名 + 函数名 + 序号 |
| 地址反查 | `ResolveApiAddress()`：将任意地址反查为 DLL 名 + 函数名 + 序号 |
| 输出结构 | 构建按模块分组的 `vector<ImportModule>` 导入树，统计解析成功 / 失败数 |

---

### 8. IAT 自动搜索（`IATSearch.cpp / IATSearch.h`）

两种策略自动定位目标模块的 IAT：

| 策略 | 说明 |
|------|------|
| 策略 1：PE 导入目录 | 直接读取 `IMAGE_DIRECTORY_ENTRY_IMPORT` 获取 IAT 位置（未被抹除时） |
| 策略 2：内存扫描 | 遍历模块内存，识别连续 API 指针聚集区，统计命中量定位 IAT |

返回 IAT 虚拟地址、RVA 和大小。

---

### 9. 导入表重建（`ImportRebuilder.cpp / ImportRebuilder.h`）

- 向转存的 PE 追加新 `.SCY` 节
- 写入标准 `IMAGE_IMPORT_DESCRIPTOR` 数组 + Original/First Thunk + 函数名字符串
- 更新 PE 数据目录中的导入表条目（RVA + 大小）
- 支持 32 位（4 字节 Thunk）和 64 位（8 字节 Thunk）PE

---

### 10. 交互式命令行会话（`InteractiveSession.cpp / InteractiveSession.h`）

```
用法: DumperClient.exe [--debug] [PID]
```

完整命令集：

| 命令 | 功能 |
|------|------|
| `loaddriver [路径]` | 加载指定 .sys 驱动或内置驱动，成功后自动重连 |
| `ps [关键字] [-n N]` | 枚举进程（驱动模式下内核枚举），支持关键字过滤和条数限制 |
| `attach <PID>` | 附加进程：打开进程 → 枚举模块 → 获取进程信息 → 推断 OEP |
| `detach` | 脱离当前目标进程 |
| `dump [文件]` | 转存主模块（默认文件名含时间戳） |
| `dumpmod <模块名> [文件]` | 转存任意指定模块 |
| `dumpmem <地址> <大小> [文件]` | 转存任意内存区域为二进制文件 |
| `iatsearch` | 自动搜索 IAT 位置（两种策略） |
| `getimports` | 解析并打印导入表（需先执行 `iatsearch`） |
| `fixdump [文件]` | **一键完整流程**：转存 → 搜索 IAT → 解析导入 → 重建导入表 → 保存最终可用 PE |
| `perebuild <文件>` | 对已转存 PE 文件重建节对齐 |
| `list` | 列出当前附加进程的模块列表 |
| `threads` | 枚举线程（驱动模式下内核枚举） |
| `context <TID>` | 获取线程寄存器状态（RAX-R15、RIP、EFLAGS、段寄存器） |
| `info` | 获取进程信息（PEB / ImageBase / EntryPoint / WoW64 / PPID） |
| `oep [地址]` | 查看或手动设置 OEP（RVA） |
| `query <地址>` | 查询内存区域信息（状态 / 保护 / 类型 / 大小） |
| `debug` | 切换调试日志开关 |
| `help` | 显示帮助 |
| `quit` | 退出会话 |
| `shutdown` | 发送关闭命令给驱动 → 驱动释放资源 → 退出 |

---

### 11. 通用工具（`ClientUtils.cpp / ClientUtils.h`）

- 路径处理：`GetFileName`、`GetFileNameWithoutExt`
- 命令行分词：`TokenizeLine`（支持引号包裹的路径）
- 大小写不敏感子串搜索
- 内存区域转存辅助（`DumpMemoryRegion`）
- PE `SizeOfImage` 读取辅助

---

## 典型使用流程

### 一键转存受保护进程

```
# 启动（需管理员权限）
DumperClient.exe

# 加载内置驱动（需关闭 Secure Boot / 开启测试签名）
> loaddriver

# 查找目标进程
> ps game.exe

# 附加目标进程
> attach 1234

# 查看当前 OEP（如需手动修正）
> oep 0x123456

# 一键转存并重建导入表
> fixdump

# 对输出文件重建节对齐（可选）
> perebuild game_SCY_20260410_120000.exe
```

---

## 通信协议（`Common/DumperProtocol.h`）

- 协议版本：`DUMPER_PROTOCOL_VERSION = 3`，版本不匹配强制拒绝
- 通信方式：4 MB 命名共享内存段 + 双向 `SynchronizationEvent`
- 共享内存布局：`DUMPER_SHARED_HEADER`（命令 + 状态 + 参数联合体）+ 紧随其后的数据缓冲区
- 支持命令数：15 条（覆盖进程操作、内存读写、模块 / 线程 / 进程枚举等）

## 许可证

本项目基于 MIT License 开源，详见 [LICENSE](LICENSE)。
