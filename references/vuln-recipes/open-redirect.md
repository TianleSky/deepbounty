# 开放重定向增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-open-redirect/SKILL.md`。无强制检查点（vt_prefix 无映射），按通用证据标准。

## 最优来源

- BountyGrimoire `.claude/skills/find-callback`（双斜杠/Unicode 点/十进制 IP/OAuth redirect_uri 最全）
- strix `open_redirect.md`（userinfo/反斜杠/IDN/双重编码矩阵 + OAuth 劫持链）

## 增量 1：绕过矩阵（BountyGrimoire + strix 合订）

| 过滤形态 | 绕过族 |
|---|---|
| 黑名单域名 | 子域拼接（`evil.com.target.com`）、后缀（`target.com.evil.com`）、userinfo（`target.com@evil.com`） |
| 必须以 / 开头 | `//evil.com`（协议相对）、`/\/evil.com`、`\\evil.com`（浏览器当 // 处理） |
| 白名单域名 | 白名单域上的开放重定向跳板、URL 解析差异（`@`、`#`、多重 `?`） |
| 编码过滤 | 双重 URL 编码、Unicode 点（`evil。com` 全角点）、IDN 同形字 |
| IP 过滤 | 十进制 IP（`http://2130706433/`）、八进制/十六进制、IPv6 `[::]` |
| 路径拼接 | `/%5cevil.com`、`/%09/evil.com`（控制字符） |

## 增量 2：OAuth redirect_uri 升级链（strix，危害放大关键）

裸开放重定向多数 SRC 低危；升级为 **OAuth token 劫持** 才高危：
1. 找 OAuth 客户端的 redirect_uri 校验弱点（子域通配/路径前缀/参数注入）
2. 链到开放重定向 → 授权码/token 被带到攻击者域
3. 配合 `response_type=token`（隐式流）直接截 access_token
判定：能拿到真实授权码/token = 高危；仅 302 跳转 = 低危

## 增量 3：参数与功能点清单（BountyGrimoire）

高发参数：`redirect`/`redirect_uri`/`url`/`next`/`return`/`returnTo`/`continue`/`dest`/
`callback`/`goto`/`target`/`rurl`/`forward`。
高发功能点：登录后跳转、登出跳转、OAuth 回调、支付回调、邮件链接点击追踪、短链服务。

## 判定纪律

- 证据 = 完整请求 + 302/200 响应（Location 头指向外部域）+ 浏览器实际跳转截图
- javascript:/data: scheme 跳转成功 = 升级 XSS 链，单独标注
