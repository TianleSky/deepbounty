# JWT 增量手册（DeepBounty 吸收版）

> 基线：Claude-BugHunter `hunt-jwt-crypto/SKILL.md`。检查点映射：JWT001 算法/签名缺陷 / JWT002 敏感信息或越权利用。

## 最优来源

- communitytools `skills/`（13 个 JWT 场景文件，全谱最全）
- pentest-agents `skills/hunt-oauth/SKILL.md`（644 行：CVE 案例 + 逐步狩猎法）
- Agentic-Bug-Hunter `bughunter/tools/jwt_scanner.py`（离线锻造工具）

## 增量 1：全谱攻击清单（communitytools 13 场景）

| 攻击 | 要点 |
|---|---|
| alg=none | `eyJhbGciOiJub25lIn0` 头 + 空签名段；库版本差异（大小写变体 `None`/`NONE`） |
| RS256→HS256 混淆 | 公钥当 HMAC 密钥；公钥从 JWKS 端点/证书透明度日志取 |
| jku 注入 | 头中 `jku` 指向攻击者 JWKS；配合开放重定向/URL 校验绕过 |
| kid 注入 | 路径穿越（`kid=../../dev/null` 空密钥）、SQL 注入、命令注入三变体 |
| x5u/x5c 注入 | 自签证书嵌入头 |
| psychic-signatures | ECDSA 全零 r/s（CVE-2022-21449，Java 15-18） |
| ECDSA nonce 复用 | 两条同 k 签名恢复私钥（收集签名对做格攻击） |
| JWE 嵌套/降级 | JWE→JWS 降级、RSA-OAEP 预言机 |
| 弱密钥爆破 | jwt_scanner.py / hashcat 16500 模式字典爆破 |
| 声明篡改 | `sub`/`role`/`tenant` 越权改写（配合 IDOR 类） |
| exp/nbf 缺失 | 永不过期 token 重放（交叉 REPLAY 类） |
| aud/iss 校验缺失 | 跨服务 token 混用 |
| 密钥泄露 | 源码/配置/JS 中的硬编码密钥（交叉 info-leak） |

## 增量 2：狩猎顺序（pentest-agents）

解码看声明 → 测 alg=none → 测算法混淆 → 弱密钥爆破 → kid/jku/x5u 注入 →
声明篡改越权 → 过期/重放。每步失败记录死因（对齐 deepbounty death_cause 分类）。

## 增量 3：工具化（Agentic-Bug-Hunter）

`jwt_scanner.py` 离线跑：输入 token 自动试 none/混淆/字典爆破，输出可利用变体 token——
miner 直接调用，结果贴进矩阵 basis。

## 判定纪律

- JWT001 通过标准：伪造 token 被接受（响应 200 且身份为伪造值），仅解码成功不算
- JWT002 必须落到具体越权或数据访问（交叉 AUTHZ/IDOR 证据标准）
