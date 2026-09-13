---
name: aliyun-oss-static-deploy
description: 把纯静态站点（dist/ 或 web/）部署到阿里云 OSS + 自定义域名 + HTTPS 证书，并打通 GitHub Actions 自动部署与证书自动续期。当用户说「推到阿里云 / 上线 / 部署到 OSS / 绑自定义域名 / 签 SSL 证书 / 配置 Actions 自动部署 / 静态站 HTTPS」时使用。
agent_created: true
---

# 静态站部署阿里云 OSS + 自定义域名 HTTPS

适用：无后端的纯静态站点（dist/、web/、out/、build/）。需要服务端渲染或接口的走函数计算 FC，不在本技能范围。

## 0. 开工前先确认（缺哪项问哪项，不要猜）

| 项 | 怎么拿到 |
|---|---|
| AccessKey ID / Secret | 只从环境变量 `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET` 读；用户没给就问，**绝不写进任何文件、不打印、不进 git** |
| 地域 region | 默认 `oss-cn-hongkong`。**免备案的刚需 → 用香港**；大陆地域绑自定义域名必须备案，且部分账号策略会拦公开读 |
| Bucket 名 | 全局唯一，被占用会 409，换名重来即可 |
| 自定义域名 | 子域即可（如 `case.example.com`），根域也支持但 `dns_rr` 要填 `@` |
| 静态产物目录 | 构建一次确认存在（如 `dist/index.html`） |

依赖（一次性）：
`pip install oss2 acme josepy cryptography alibabacloud_alidns20150109 alibabacloud_cas20200407 alibabacloud_ram20150501 pynacl`

## 1. 建桶 → 上传 → 配静态托管

建桶时给 `public-read` ACL 并指定香港地域；上传时按扩展名设 `Content-Type`（OSS 不猜，猜错浏览器行为很怪）：

| 文件 | Cache-Control | 理由 |
|---|---|---|
| `index.html` / `*.html` / 数据文件 | `no-cache` | 内容常变，改完立刻生效 |
| `*.js` / `*.css` | `public, max-age=300` | 基本不变，省回源 |

**必须设静态网站托管**（`PUT ?website`，IndexDocument=`index.html`，ErrorDocument=`404.html`）；
不设的话访问域名根路径返回的是 XML 对象列表，而不是首页。

## 2. 关键坑：公开访问 403

新建桶默认 `BlockPublicAccess=true` —— 现象：匿名访问 403，且 `PutBucketPolicy` 也被拒
（`Put public bucket policy is not allowed`），此时**改 ACL 没用**，必须关掉桶级阻止公共访问：

```
DELETE https://<bucket>.oss-<region>.aliyuncs.com/?publicAccessBlock   → 204 即成功
GET    https://<bucket>.oss-<region>.aliyuncs.com/?publicAccessBlock   → 确认 <BlockPublicAccess>false</BlockPublicAccess>
```

排查顺序：先 `GET ?publicAccessBlock` 看是不是 true → 关掉 → 再匿名 `curl` 一次确认 200。

## 3. 域名 + HTTPS 证书

顺序不能反：**先加 CNAME 记录**指向 `<bucket>.oss-<region>.aliyuncs.com`，等解析生效后再绑域名。

- 走 CDN 加速：CNAME 指 CDN 域名，证书在 CDN 上配（部署后记得刷新目录缓存 `/`）。
- 直连 OSS：CNAME 指桶的标准域名。**注意 OSS 按 Host 头匹配自定义域名**，CNAME 指向 OSS 海外公共入口
  （如 `*.thepacificphs.com`）时自定义证书不生效，必须指到 `<bucket>.oss-<region>.aliyuncs.com`。

证书两条路：

1. **已有通配证书**（推荐，多站点共用一张）——只做分发，不重签：上传 CAS 拿到 `cert_id`，
   再用 `PutCname` 绑到桶，绑定前自动写 `_dnsauth.<子域>` TXT 做归属验证。
   注意 `force` 字段必须是字符串 `'true'`，传 `1` 会触发 `MalformedXML` 并盖住真正的报错。
2. **没有证书**——用 `scripts/cert_manager.py` 一步到位：DNS-01 签发（alidns 自动加 TXT）→ 上传 CAS
   → 绑定 OSS（可选同步推 FC 自定义域名）。泛域名 `example.com + *.example.com` 一次覆盖所有子域，
   后续新增站点只加一行分发目标，不必重签。

```bash
# 签发泛域名证书并绑定到 OSS 自定义域名
python scripts/cert_manager.py --root example.com --email you@example.com \
    --bucket my-site-hk --region cn-hongkong --domain www.example.com

# 证书已存在、只做分发（续期后常用）
python scripts/cert_manager.py --root example.com --domain www.example.com --targets oss
```

ACME 证书只有 90 天，脚本剩余 >30 天自动跳过；到期前重签并重新分发。

## 4. GitHub Actions 自动部署

先查现状再动手，别猜（只能读名字，读不到值）：

```bash
TOKEN=$(grep -o "gho_[A-Za-z0-9]*" ~/.git-credentials)
curl --noproxy '*' -H "Authorization: Bearer $TOKEN" \
  https://api.github.com/repos/<owner>/<repo>/actions/{secrets,variables}
```

- **Variables**（明文，直接 POST）：`OSS_BUCKET`、`OSS_REGION`。
- **Secrets**：先 `GET /actions/secrets/public-key` 拿 `key_id` + 公钥，再用 PyNaCl `SealedBox` 加密后 PUT
  （`scripts/set_github_secret.py` 封装了这段）。
- **公开仓库绝不放主账号 AK**：先用 RAM 建专用子账号，策略只给这一个桶的
  `oss:PutObject / GetObject / DeleteObject / ListObjects` + `oss:PutBucketWebsite / GetBucketWebsite`，
  外加全局 `oss:ListBuckets`（部署脚本的凭证自检要用）；Secret 用后即删本地副本。
- 验证：`POST /actions/workflows/<file>/dispatches` 手动触发（204 成功）→
  `GET /actions/runs/<id>/jobs` 看每个 step 的 conclusion，确认部署步骤真的跑了而不是被 skip。

## 5. 证书自动续期

把 `scripts/cert_manager.py` 挂到每日定时任务（Windows 上 `schtasks` 常被环境禁用，优先用宿主自带的
定时/自动化能力，例如 WorkBuddy 自动化）。脚本幂等：没到期就退出，到期才重签 + 分发。

## 附：验收清单

```bash
curl -o /dev/null -w "%{http_code} %{ssl_verify_result}\n" https://<域名>/   # 200 且 ssl_verify_result=0
curl -s https://<域名>/data.js | wc -c        # 与本地构建产物字节数一致
curl -o /dev/null -w "%{http_code}\n" https://<域名>/not-exist-page          # 404 页生效
```

## 附：常见错误对照

| 报错 | 真实原因 |
|---|---|
| 匿名访问 403 + `bucket acl` | 桶级 `BlockPublicAccess=true`，须 `DELETE ?publicAccessBlock` |
| `Put public bucket policy is not allowed` | 账号级策略限制，改 ACL 即可，不必强求 bucket policy |
| 根路径返回 XML 列表 | 没配静态网站托管 |
| `MalformedXML` 于 PutCname | `force` 传了非字符串；改 `'true'` 后才会暴露真正的 `NeedVerifyDomainOwnership` |
| 绑域名报 `DomainNameNotResolved` | CNAME 还没生效，先加解析等生效 |
| 自定义证书不生效 | CNAME 指到了 OSS 海外公共入口，改指 `<bucket>.oss-<region>.aliyuncs.com` |
| 上传后线上还是旧的 | 走了 CDN 未刷新，或浏览器缓存了 `max-age` 资源 |
