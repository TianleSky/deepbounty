# 漏洞报告模板

> 漏洞挖掘阶段（含威胁收敛阶段的补测/绕过突破）确认存在漏洞时，按本模板撰写报告，文件名 = 报告号
> （`reports/{vuln_id}.md`），并用 `register_report.py` 登记到漏洞报告清单。
>
> **铁律**：证据**零脱敏**。请求与响应从当次实测原文整段贴入（全部请求头，含 Cookie、Authorization 及一切自定义认证头；完整 body；完整响应头与响应体）。
> 禁止打码、星号、省略号、只留「关键片段」、改写字段值。代理日志里的 `RESPONSE BODY (preview: 200Byte only)` **不能**当报告证据。
> **严禁幻觉式验证**。报告须含复现步骤 + 可直接重放的完整报文 + **危害边界**（L3 打到哪、哪条客观打不通）。
> 写报告前必须过 [src-report-gate.md](src-report-gate.md)。缺全文、打过码、或过不了 SRC 门的，质量门禁拒绝。

---

# 漏洞报告 VULN-VD-URL00021-0001

## 报告元信息

- 报告ID：VULN-VD-URL00021-0001
- 标题：订单创建接口价格篡改导致 1 元购买任意商品
- 漏洞类型：业务逻辑 / 越权
- 危害等级：严重（critical）
- 关联 URLID：URL00021
- 关联威胁：THREAT0012（消账到本报告的威胁，无则可省略）

## 漏洞摘要

一句话概述：攻击者创建订单时可篡改 couponId 引用他人高额优惠券，使 payAmount 降至 1 元。

## 漏洞描述

详细说明漏洞原理、触发条件与受影响范围：服务端创建订单时未校验 couponId 与当前用户的归属关系，
且最终金额由客户端传入的 couponId 决定……

## 复现步骤

### 环境要求

- 账号：user01（买家）；目标接口：POST /api/order/create
- 前置数据：……

### 完整步骤（填写要求：应尽可能按照人工操作的步骤进行，说明通过浏览器操作路径如何访问到目标接口，拦截篡改什么操作的请求等）

1. 登录 user01，抓取创建订单请求。
2. 将 couponId 改为枚举得到的他人大额券 ID 88231。
3. 发送请求，payAmount 由 299 变为 1。
4. 完成支付，订单成立。

### 完整请求（零脱敏，从当次实测原文粘贴，禁止改写成省略号）

```http
POST /api/order/create HTTP/1.1
Host: shop.example.com
Cookie: SESSION=8f3c1a9e0b74d2c6a15e91f0
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.signature
Content-Type: application/json
Content-Length: 62

{"skuId":1001,"count":1,"addressId":55,"couponId":88231}
```

上面只示范「字段要写全」。真实报告必须换成日志/重放输出里的原值，Cookie 和 Token 一个字符都不能改。

## 危害说明（填写要求：必须是基于实际观察发现的危害，不能是纯假设或推理）

- 可 1 元购买任意标价商品，直接经济损失。
- 优惠券 ID 可枚举，影响面覆盖全部在售商品。

## 危害边界（L3：打到哪一档 / 哪条客观打不通）

- 已证明：券 ID 可枚举，payAmount 真实降为 1 并下单成功。
- 未打通（客观边界）：……（无限制原则——不存在"安全等级不允许"这一理由，只写客观打不通的）。

## 验证证据（零脱敏：请求与响应都贴全文，必须能直接看到危害）

- **请求**：见上「完整请求」。头和 body 与当次重放字节一致。
- **响应全文**（状态行、全部响应头、完整 body，不要删字段）：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: SESSION=8f3c1a9e0b74d2c6a15e91f0; Path=/

{"orderId":10293,"payAmount":1,"skuId":1001}
```

- **证据来源**：写明这条全文出自哪次重放（curl/python 原始输出，或代理日志里**未截断**的那一条）。
  只有 200 字节 preview、或正文里出现 `...` / `***` / 「关键片段」的，审核不通过。



## 修复建议

- 校验 couponId 归属当前用户且未使用。
- 金额与优惠在服务端二次核验，不接受客户端传入的最终金额。

## SRC提交稿（可直接粘贴到 SRC 表单，缺本节不得登记）

> 这一节就是提交物。标题、漏洞 URL、逐步流程、完整请求包、完整响应包、修复建议六项都要有，且与上面证据同源、零脱敏。

- **标题**（≤50 字，写清接口 + 后果）：订单接口篡改他人优惠券致 1 元下单
- **漏洞 URL**：`POST https://shop.example.com/api/order/create`
- **复现流程**（从浏览器登录写到看到危害，每步可照做）：
  1. 浏览器登录买家账号 user01，进入下单页。
  2. 提交订单时拦截 `POST /api/order/create`。
  3. 把 body 里 `couponId` 改成枚举到的他人券 `88231`，原样重放。
  4. 响应 `payAmount` 从 299 变为 1，订单 `10293` 成立。
- **完整请求包**（请求行 + 全部头 + 完整 body，独立成段，可整段贴进 SRC「请求包」栏）：

```http
POST /api/order/create HTTP/1.1
Host: shop.example.com
Cookie: SESSION=8f3c1a9e0b74d2c6a15e91f0
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.signature
Content-Type: application/json
Content-Length: 62

{"skuId":1001,"count":1,"addressId":55,"couponId":88231}
```

- **完整响应包**（状态行 + 全部响应头 + 完整 body，危害字段必须在正文里看得见）：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"orderId":10293,"payAmount":1,"skuId":1001}
```

- **修复建议**：服务端校验券归属与金额，不信任客户端传入的券和应付金额。

## 参考资料

- OWASP API1:2023 Broken Object Level Authorization
- CWE-639 Authorization Bypass Through User-Controlled Key
