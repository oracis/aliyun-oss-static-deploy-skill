#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""aliyun-oss-static-deploy-skill 全量测试套件（unittest，零新依赖）。

两层设计：
  A. 离线单测（默认全跑）：不联网、不需要真实 AK。
     - RPC V1 签名：从捕获的 URL 独立复算 HMAC-SHA1 签名比对
     - V3 ACS3-HMAC-SHA256 签名：从捕获的 headers 独立复算比对（防回归）
     - DNS/CAS/FC 封装、dns_upsert 幂等三分支、FC 分页
     - cert_manager：FC 更新"GET 合并 -> PUT -> 复核"语义（mock R.fc_*）
     - deploy_oss：纯函数 + ensure_bucket/verify_object/backup_object/verify_public（FakeBucket）
     - bind_domain：norm_region/_Cert 约定/wait_txt 归一化
     - 全脚本 py_compile 自检
  B. 在线只读冒烟（--live 或 ALIYUN_LIVE=1 才跑，需要真实 AK）：
     DNS/CAS/FC 列表、桶信息、站点 HTTPS 200 与语义标记——全部只读。

用法：
    python tests/test_aliyun.py            # 离线全套
    python tests/test_aliyun.py --live     # 离线 + 在线冒烟
    python -m unittest discover -s tests   # CI（离线）
"""
import base64
import calendar
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest import mock
from urllib.parse import urlparse, parse_qsl, quote

warnings.simplefilter("ignore", ResourceWarning)  # 测试脚本大量临时文件，噪音过滤

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
SKILL_ROOT = os.path.dirname(HERE)
sys.path.insert(0, SCRIPTS)

# 离线签名测试用假凭据（roa_call/call 要求非空）；真实 AK 只在 --live 用
os.environ.setdefault("ALIBABA_CLOUD_ACCESS_KEY_ID", "TESTAKID")
os.environ.setdefault("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "TESTSK/secret")

LIVE = "--live" in sys.argv or os.environ.get("ALIYUN_LIVE") == "1"
if "--live" in sys.argv:
    sys.argv.remove("--live")

import aliyun_rpc as R  # noqa: E402

# 在线冒烟的目标（可用环境变量覆盖）
LIVE_ROOT = os.environ.get("ALIYUN_TEST_ROOT", "ydtgo.top")
LIVE_BUCKET = os.environ.get("OSS_TEST_BUCKET", "esp32-handbook-hk")
LIVE_SITE = os.environ.get("SITE_TEST_URL", "https://esp32.ydtgo.top/")
LIVE_SITE_MARKER = os.environ.get("SITE_TEST_MARKER", "大模型 Agent")
LIVE_FC_REGION = os.environ.get("FC_TEST_REGION", "cn-hongkong")

# bind_domain 在 import 时会清代理环境变量，测试结束时还原
_PROXY_KEYS = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
               "ALL_PROXY", "all_proxy"]
_PROXY_SNAPSHOT = {k: os.environ.get(k) for k in _PROXY_KEYS}


def tearDownModule():
    for k, v in _PROXY_SNAPSHOT.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _mk_resp(payload=None, status=200, json_fail=False, text=None):
    """构造 mock HTTP 响应。json_fail=True 模拟非 JSON 响应体。"""
    r = mock.MagicMock()
    r.status_code = status
    body = json.dumps(payload if payload is not None else {})
    r.text = text if text is not None else body
    if json_fail:
        r.json.side_effect = ValueError("not json")
    else:
        r.json.return_value = payload if payload is not None else {}
    return r


def _patch_session(resp=None, capture=None):
    """patch requests.Session。

    resp: mock 响应对象（_mk_resp 产物），供 session.get / session.request 返回。
          注意不要用 callable(resp) 判断——MagicMock 本身就是 callable，
          会被误调用返回裸子 mock，这是本次测试开发中真实踩过的坑。
    capture: dict，roa_call 时收到 method/url/data/headers，call 时收到 url。
    """
    sess = mock.MagicMock()

    def fake_get(url, timeout=None):
        if capture is not None:
            capture["url"] = url
        return resp

    def fake_req(method, url, data=None, headers=None, timeout=None):
        if capture is not None:
            capture.update(method=method, url=url, data=data,
                           headers=dict(headers or {}))
        return resp

    sess.get.side_effect = fake_get
    sess.request.side_effect = fake_req
    S = mock.MagicMock()
    S.return_value = sess
    return mock.patch("requests.Session", S)


# ==================== A1. RPC V1 签名（aliyun_rpc.call）====================

class TestRpcV1Signature(unittest.TestCase):
    """GET&%2F& + HMAC-SHA1(SK+"&")——从捕获的 URL 独立复算。"""

    def _call(self, params=None):
        cap = {}
        with _patch_session(resp=_mk_resp({"RequestId": "x"}), capture=cap):
            R.call("alidns.aliyuncs.com", "2015-01-09",
                   "DescribeDomainRecords", params or {"DomainName": "a.b"})
        return cap["url"]

    def test_signature_recomputable(self):
        url = self._call({"DomainName": "a.b", "PageSize": 20})
        self.assertTrue(url.startswith("https://alidns.aliyuncs.com/?"))
        pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
        q = dict(pairs)
        sig = q.pop("Signature")
        for k in ("Action", "Version", "Format", "AccessKeyId",
                  "SignatureMethod", "SignatureVersion", "SignatureNonce",
                  "Timestamp"):
            self.assertIn(k, q)
        self.assertEqual(q["Action"], "DescribeDomainRecords")
        self.assertEqual(q["SignatureMethod"], "HMAC-SHA1")
        # Timestamp 是 UTC ISO8601（用 calendar.timegm，mktime 会按本地时区算差 8 小时）
        import time as _t
        ts = _t.strptime(q["Timestamp"], "%Y-%m-%dT%H:%M:%SZ")
        self.assertLess(abs(_t.time() - calendar.timegm(ts)), 300)
        # 独立复算
        canonical = "&".join("%s=%s" % (R._pe(k), R._pe(v))
                             for k, v in sorted(q.items()))
        sts = "GET&%2F&" + R._pe(canonical)
        expect = base64.b64encode(hmac.new(
            (R.SK + "&").encode(), sts.encode(), hashlib.sha1).digest()).decode()
        self.assertEqual(sig, expect)

    def test_canonical_sorted_in_url(self):
        url = self._call({"DomainName": "a.b", "PageSize": 20})
        query = urlparse(url).query
        keys = [k for k, _ in parse_qsl(query, keep_blank_values=True)
                if k != "Signature"]
        self.assertEqual(keys, sorted(keys))

    def test_space_encoded_as_percent20(self):
        url = self._call({"DomainName": "a b"})
        self.assertIn("DomainName=a%20b", url)
        self.assertNotIn("+", urlparse(url).query.replace("%2B", ""))

    def test_missing_credentials_raises(self):
        with mock.patch.object(R, "AK", ""), mock.patch.object(R, "SK", ""):
            with self.assertRaises(RuntimeError):
                R.call("alidns.aliyuncs.com", "2015-01-09", "X", {})

    def test_api_error_raises_with_code(self):
        with _patch_session(resp=_mk_resp(
                {"Error": {"Code": "InvalidAction", "Message": "bad"}}, 400)):
            with self.assertRaises(RuntimeError) as cm:
                R.call("alidns.aliyuncs.com", "2015-01-09", "Bad", {})
        self.assertIn("InvalidAction", str(cm.exception))


class TestRpcEncoding(unittest.TestCase):
    def test_space(self):
        self.assertEqual(R._pe("a b"), "a%20b")

    def test_tilde_kept(self):
        self.assertEqual(R._pe("a~b"), "a~b")

    def test_plus_encoded(self):
        self.assertEqual(R._pe("a+b"), "a%2Bb")

    def test_safe_chars(self):
        self.assertEqual(R._pe("A-z._9"), "A-z._9")

    def test_none_params_filtered(self):
        cap = {}
        with _patch_session(resp=_mk_resp({}), capture=cap):
            R.call("alidns.aliyuncs.com", "2015-01-09", "X",
                   {"A": None, "B": 1})
        self.assertNotIn("A=", urlparse(cap["url"]).query)


# ==================== A2. V3 ACS3 签名（aliyun_rpc.roa_call）====================

FC_EP = "fcv3.cn-hongkong.aliyuncs.com"
FC_PATH = "/2023-03-30/custom-domains/pan.example.com"


class TestRoaV3Signature(unittest.TestCase):
    """CanonicalRequest 各行独立重算，与 Authorization 里的 Signature 比对。"""

    def _req(self, method="PUT", path=FC_PATH, body=None, query=None,
             status=200, payload=None, json_fail=False, text=None):
        cap = {}
        resp = _mk_resp(payload, status, json_fail=json_fail, text=text)
        with _patch_session(resp=resp, capture=cap):
            out = R.roa_call(FC_EP, "2023-03-30", "UpdateCustomDomain",
                             method, path, body=body, query=query)
        return cap, out

    def _auth_parts(self, headers):
        auth = headers["Authorization"]
        algo, rest = auth.split(" ", 1)
        parts = dict(p.split("=", 1) for p in rest.split(","))
        return algo, parts

    def test_signature_recomputable_with_body(self):
        body = {"protocol": "HTTP,HTTPS",
                "certConfig": {"certName": "n", "privateKey": "k"}}
        cap, _ = self._req(body=body, query={"limit": 50})
        h = cap["headers"]
        algo, parts = self._auth_parts(h)
        self.assertEqual(algo, "ACS3-HMAC-SHA256")
        self.assertEqual(parts["Credential"], R.AK)
        signed = parts["SignedHeaders"].split(";")
        self.assertEqual(signed, sorted(signed))
        # 独立复算（按官方文档规则，不复用 aliyun_rpc 内部逻辑）
        canon_headers = "".join("%s:%s\n" % (k, h[k]) for k in signed)
        uri = "/".join(quote(seg, safe="") for seg in FC_PATH.split("/"))
        q = "&".join("%s=%s" % (quote(k, safe=""), quote(str(v), safe=""))
                     for k, v in sorted({"limit": 50}.items()))
        payload_hash = hashlib.sha256(cap["data"]).hexdigest()
        canonical = "\n".join(["PUT", uri, q, canon_headers,
                               ";".join(signed), payload_hash])
        sts = "ACS3-HMAC-SHA256\n" + hashlib.sha256(
            canonical.encode("utf-8")).hexdigest()
        expect = hmac.new(R.SK.encode("utf-8"), sts.encode("utf-8"),
                          hashlib.sha256).hexdigest()
        self.assertEqual(parts["Signature"], expect)
        # 必带头
        for k in ("host", "x-acs-action", "x-acs-version", "x-acs-date",
                  "x-acs-signature-nonce", "x-acs-content-sha256"):
            self.assertIn(k, signed, "缺必签头 %s" % k)
        self.assertEqual(h["host"], FC_EP)
        self.assertEqual(h["x-acs-action"], "UpdateCustomDomain")
        self.assertEqual(h["x-acs-version"], "2023-03-30")
        self.assertEqual(h["x-acs-content-sha256"], payload_hash)
        # body 原样 JSON bytes
        self.assertEqual(cap["data"],
                         json.dumps(body, ensure_ascii=False).encode("utf-8"))
        self.assertEqual(h.get("content-type"), "application/json")
        # URL 拼装
        self.assertTrue(cap["url"].startswith("https://" + FC_EP + uri + "?"))

    def test_get_no_body(self):
        cap, _ = self._req(method="GET", body=None, query={"limit": 100})
        self.assertIsNone(cap["data"])
        self.assertNotIn("content-type", cap["headers"])
        self.assertEqual(cap["headers"]["x-acs-content-sha256"],
                         hashlib.sha256(b"").hexdigest())
        self.assertTrue(cap["url"].endswith(
            "?limit=100") or "limit=100" in cap["url"])

    def test_uri_special_chars_encoded(self):
        path = "/2023-03-30/custom-domains/中文.example.com"
        cap, _ = self._req(method="GET", path=path)
        self.assertNotIn("中文", cap["url"])
        self.assertIn("%E4%B8%AD%E6%96%87", cap["url"])

    def test_query_sorted(self):
        cap, _ = self._req(method="GET", query={"zz": 1, "aa": 2, "mm": 3})
        qs = urlparse(cap["url"]).query
        keys = [k for k, _ in parse_qsl(qs, keep_blank_values=True)]
        self.assertEqual(keys, sorted(keys))

    def test_none_query_value_filtered(self):
        cap, _ = self._req(method="GET", query={"a": None, "b": 1})
        qs = urlparse(cap["url"]).query
        self.assertNotIn("a=", qs)
        self.assertIn("b=1", qs)

    def test_error_2xx_boundary(self):
        with self.assertRaises(RuntimeError) as cm:
            self._req(status=404, payload={"Code": "DomainNotFound",
                                           "ErrorMessage": "no such domain"})
        msg = str(cm.exception)
        self.assertIn("UpdateCustomDomain", msg)
        self.assertIn("DomainNotFound", msg)
        self.assertIn("no such domain", msg)

    def test_error_3xx_rejected(self):
        with self.assertRaises(RuntimeError):
            self._req(status=302, payload={})

    def test_non_json_error_falls_back_to_text(self):
        with self.assertRaises(RuntimeError) as cm:
            self._req(status=502, payload={}, json_fail=True,
                      text="<html>gateway error</html>")
        self.assertIn("gateway error", str(cm.exception))

    def test_missing_credentials_raises(self):
        with mock.patch.object(R, "AK", ""):
            with self.assertRaises(RuntimeError):
                R.roa_call(FC_EP, "2023-03-30", "X", "GET", "/x")


class TestV3Encoding(unittest.TestCase):
    def test_space(self):
        self.assertEqual(R._v3enc("a b"), "a%20b")

    def test_star(self):
        self.assertEqual(R._v3enc("a*b"), "a%2Ab")

    def test_tilde_kept(self):
        self.assertEqual(R._v3enc("a~b"), "a~b")

    def test_unreserved_kept(self):
        self.assertEqual(R._v3enc("A-z_9."), "A-z_9.")

    def test_chinese_encoded(self):
        out = R._v3enc("中文")
        self.assertNotIn("中", out)
        self.assertEqual(out, "%E4%B8%AD%E6%96%87")


# ==================== A3. DNS / CAS 封装 ====================

class TestDnsUpsert(unittest.TestCase):
    """幂等三分支：值相同不写、值不同 Update、不存在 Add。"""

    def test_same_value_no_write(self):
        recs = [{"RecordId": "r1", "RR": "www", "Type": "CNAME",
                 "Value": "t.aliyuncs.com"}]
        with mock.patch.object(R, "dns_list", return_value=recs) as ml, \
             mock.patch.object(R, "call") as mc:
            rid = R.dns_upsert("a.b", "www", "CNAME", "t.aliyuncs.com")
        self.assertEqual(rid, "r1")
        mc.assert_not_called()          # 没有任何写操作

    def test_different_value_updates(self):
        recs = [{"RecordId": "r1", "RR": "www", "Type": "CNAME",
                 "Value": "old.aliyuncs.com"}]
        with mock.patch.object(R, "dns_list", return_value=recs), \
             mock.patch.object(R, "call", return_value={}) as mc:
            rid = R.dns_upsert("a.b", "www", "CNAME", "new.aliyuncs.com")
        self.assertEqual(rid, "r1")
        args = mc.call_args[0]
        self.assertEqual(args[2], "UpdateDomainRecord")
        self.assertEqual(args[3]["Value"], "new.aliyuncs.com")

    def test_missing_adds(self):
        with mock.patch.object(R, "dns_list", return_value=[]), \
             mock.patch.object(R, "dns_add", return_value="r9") as ma:
            rid = R.dns_upsert("a.b", "www", "CNAME", "t.x")
        self.assertEqual(rid, "r9")
        ma.assert_called_once()
        args, kwargs = ma.call_args
        self.assertEqual(args[:4], ("a.b", "www", "CNAME", "t.x"))
        self.assertEqual(kwargs.get("ttl", args[4] if len(args) > 4 else None),
                         600)

    def test_type_mismatch_does_not_match(self):
        # RR 相同但 Type 不同的记录不应命中幂等分支
        recs = [{"RecordId": "r1", "RR": "www", "Type": "A",
                 "Value": "1.2.3.4"}]
        with mock.patch.object(R, "dns_list", return_value=recs), \
             mock.patch.object(R, "dns_add", return_value="r2") as ma, \
             mock.patch.object(R, "call") as mc:
            R.dns_upsert("a.b", "www", "CNAME", "t.x")
        ma.assert_called_once()
        mc.assert_not_called()

    def test_dns_delete_wraps_call(self):
        with mock.patch.object(R, "call", return_value={}) as mc:
            self.assertTrue(R.dns_delete("r1"))
        self.assertEqual(mc.call_args[0][2], "DeleteDomainRecord")


class TestCasFindCertId(unittest.TestCase):
    def _tmp(self):
        return tempfile.mkdtemp()

    def test_cas_id_txt(self):
        d = self._tmp()
        open(os.path.join(d, "cas_id.txt"), "w").write("28560188")
        self.assertEqual(R.cas_find_cert_id(d), 28560188)

    def test_state_json(self):
        d = self._tmp()
        json.dump({"cert_id": 12345},
                  open(os.path.join(d, "state.json"), "w"))
        self.assertEqual(R.cas_find_cert_id(d), 12345)

    def test_cas_id_txt_priority(self):
        d = self._tmp()
        open(os.path.join(d, "cas_id.txt"), "w").write("111")
        json.dump({"cert_id": 222}, open(os.path.join(d, "state.json"), "w"))
        self.assertEqual(R.cas_find_cert_id(d), 111)

    def test_state_json_bad_content_ignored(self):
        d = self._tmp()
        open(os.path.join(d, "state.json"), "w").write("not json{")
        self.assertIsNone(R.cas_find_cert_id(d))

    def test_missing_dir(self):
        self.assertIsNone(
            R.cas_find_cert_id(os.path.join(self._tmp(), "nope")))

    def test_cas_list_certs_params(self):
        with mock.patch.object(R, "call", return_value={
                "CertificateOrderList": [{"CertificateId": 1}]}) as mc:
            out = R.cas_list_certs("UPLOAD", keyword="ydtgo")
        self.assertEqual(out, [{"CertificateId": 1}])
        args = mc.call_args[0]
        self.assertEqual(args[2], "ListUserCertificateOrder")
        self.assertEqual(args[3]["OrderType"], "UPLOAD")
        self.assertEqual(args[3]["Keyword"], "ydtgo")


# ==================== A4. FC 封装与分页 ====================

class TestFcWrappers(unittest.TestCase):
    def test_list_pagination(self):
        pages = [
            {"customDomains": [{"domainName": "a.com"}], "nextToken": "t1"},
            {"customDomains": [{"domainName": "b.com"}], "nextToken": "t2"},
            {"customDomains": [{"domainName": "c.com"}]},
        ]
        calls = []

        def fake_roa(ep, ver, action, method, path, body=None, query=None,
                     **kw):
            calls.append(query or {})
            return pages[len(calls) - 1]

        with mock.patch.object(R, "roa_call", side_effect=fake_roa):
            out = R.fc_list_custom_domains("cn-hongkong")
        self.assertEqual([d["domainName"] for d in out],
                         ["a.com", "b.com", "c.com"])
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0].get("limit"), 100)
        self.assertEqual(calls[1].get("nextToken"), "t1")
        self.assertEqual(calls[2].get("nextToken"), "t2")

    def test_get_path(self):
        with mock.patch.object(R, "roa_call", return_value={}) as mc:
            R.fc_get_custom_domain("cn-hongkong", "pan.x.com")
        args = mc.call_args[0]
        self.assertEqual(args[0], "fcv3.cn-hongkong.aliyuncs.com")
        self.assertEqual(args[3], "GET")
        self.assertEqual(args[4], "/2023-03-30/custom-domains/pan.x.com")

    def test_update_put_body(self):
        body = {"protocol": "HTTP"}
        with mock.patch.object(R, "roa_call", return_value={}) as mc:
            R.fc_update_custom_domain("cn-hongkong", "pan.x.com", body)
        args, kwargs = mc.call_args
        self.assertEqual(args[3], "PUT")
        self.assertEqual(args[4], "/2023-03-30/custom-domains/pan.x.com")
        self.assertEqual(kwargs.get("body"), body)


# ==================== A5. cert_manager：证书工具与 FC 合并语义 ====================

def _make_cert_dir():
    """生成自签证书夹：fullchain.pem + privkey.pem（PKCS8，脚本要转传统格式）。"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.example.com")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=90))
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp(prefix="acme-test-")
    open(os.path.join(d, "fullchain.pem"), "w").write(
        cert.public_bytes(serialization.Encoding.PEM).decode())
    open(os.path.join(d, "privkey.pem"), "wb").write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return d


class TestCertTools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_dir = _make_cert_dir()

    def test_traditional_pem_not_pkcs8(self):
        import cert_manager as CM
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(
            open(os.path.join(self.cert_dir, "privkey.pem"), "rb").read(),
            password=None)
        out = CM.traditional_pem(key)
        self.assertIn("BEGIN RSA PRIVATE KEY", out)
        self.assertNotIn("BEGIN PRIVATE KEY", out)

    def test_days_left_fresh_cert(self):
        import cert_manager as CM
        days = CM.days_left(os.path.join(self.cert_dir, "fullchain.pem"))
        self.assertTrue(80 <= days <= 90, "days=%s" % days)

    def test_days_left_missing_file(self):
        import cert_manager as CM
        self.assertEqual(CM.days_left(os.path.join(self.cert_dir, "no.pem")), -1)

    def test_load_local_returns_fullchain_and_traditional_key(self):
        import cert_manager as CM
        pem, key_pem = CM.load_local(self.cert_dir)
        self.assertIn("BEGIN CERTIFICATE", pem)
        self.assertIn("BEGIN RSA PRIVATE KEY", key_pem)

    def test_wait_txt_found_first_try(self):
        import cert_manager as CM
        token = "tok-abc-123"
        fake = mock.MagicMock()
        fake.stdout = ' TXT  "tok-abc-123" '
        # cert_manager 的 subprocess 是函数内 import，只能全局 patch
        with mock.patch("subprocess.run", return_value=fake):
            self.assertTrue(CM.wait_txt("x.example.com", token, timeout=20))


class TestCertManagerFcMerge(unittest.TestCase):
    """FC 更新语义：GET 现配置 -> 只换 certConfig、其余原样带回 -> PUT -> 复核。"""

    @classmethod
    def setUpClass(cls):
        cls.cert_dir = _make_cert_dir()

    def _run_main(self, extra_args, cur_cfg, put_log, list_domains=None,
                  put_updates_state=True):
        """跑 cert_manager.main()（--targets fc），mock 掉 R.fc_*。

        put_updates_state=True：模拟真实 FC——PUT 后 GET 回来的 certName 是新值；
        False：模拟"复核不一致"（服务端没生效），应触发 SystemExit(1)。
        """
        import cert_manager as CM
        list_domains = list_domains if list_domains is not None else [
            {"domainName": "pan.example.com"}]
        state = {"cfg": dict(cur_cfg)}

        def fake_get(region, domain):
            return state["cfg"]

        def fake_put(region, domain, body):
            put_log.append((region, domain, body))
            if put_updates_state:
                state["cfg"] = dict(state["cfg"],
                                    certConfig={"certName":
                                                body["certConfig"]["certName"]})

        with mock.patch.object(CM.R, "fc_list_custom_domains",
                               return_value=list_domains), \
             mock.patch.object(CM.R, "fc_get_custom_domain",
                               side_effect=fake_get), \
             mock.patch.object(CM.R, "fc_update_custom_domain",
                               side_effect=fake_put), \
             mock.patch.object(sys, "argv",
                               ["cert_manager.py", "--root", "example.com",
                                "--email", "t@example.com",
                                "--cert-dir", self.cert_dir,
                                "--targets", "fc"] + extra_args):
            return CM.main()

    def test_merge_preserves_protocol_route_tls(self):
        cur = {
            "protocol": "HTTP,HTTPS",
            "routeConfig": {"routes": [{"path": "/*",
                                        "functionName": "svc$fn"}]},
            "tlsConfig": {"minVersion": "TLSv1.2"},
            "certConfig": {"certName": "old-cert"},
        }
        put_log = []
        rc = self._run_main([], cur, put_log)
        self.assertEqual(rc, 0)
        self.assertEqual(len(put_log), 1)
        region, domain, body = put_log[0]
        self.assertEqual(domain, "pan.example.com")   # 自动匹配
        self.assertEqual(body["protocol"], "HTTP,HTTPS")
        self.assertEqual(body["routeConfig"], cur["routeConfig"])
        self.assertEqual(body["tlsConfig"], cur["tlsConfig"])
        cc = body["certConfig"]
        self.assertEqual(cc["certName"], "example-com-le")
        self.assertIn("BEGIN CERTIFICATE", cc["certificate"])
        self.assertIn("BEGIN RSA PRIVATE KEY", cc["privateKey"])
        self.assertNotIn("BEGIN PRIVATE KEY", cc["privateKey"])  # 非 PKCS8

    def test_none_tls_omitted(self):
        cur = {"protocol": "HTTP", "routeConfig": {"routes": []},
               "tlsConfig": None}
        put_log = []
        self._run_main([], cur, put_log)
        body = put_log[0][2]
        self.assertNotIn("tlsConfig", body)
        self.assertEqual(body["protocol"], "HTTP")

    def test_explicit_domain_skips_automatch(self):
        cur = {"protocol": "HTTP"}
        put_log = []
        self._run_main(["--fc-domain", "a.example.com"], cur, put_log,
                       list_domains=[{"domainName": "b.example.com"}])
        self.assertEqual(put_log[0][1], "a.example.com")

    def test_verify_mismatch_exits(self):
        cur = {"protocol": "HTTP"}
        put_log = []
        with self.assertRaises(SystemExit) as cm:
            self._run_main([], cur, put_log, put_updates_state=False)
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(len(put_log), 1)  # PUT 已发生，只是复核不过

    def test_multiple_domains_all_updated(self):
        cur = {"protocol": "HTTP"}
        put_log = []
        self._run_main(["--fc-domain", "a.example.com",
                        "--fc-domain", "b.example.com"], cur, put_log,
                       put_updates_state=True)
        self.assertEqual([d for _, d, _ in put_log],
                         ["a.example.com", "b.example.com"])


# ==================== A6. deploy_oss：纯函数与 oss2 交互 ====================

class TestDeployPureFuncs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, SCRIPTS)
        import deploy_oss as D
        cls.D = D

    def test_norm_region(self):
        self.assertEqual(self.D.norm_region("cn-hongkong"), "oss-cn-hongkong")
        self.assertEqual(self.D.norm_region("oss-cn-hongkong"),
                         "oss-cn-hongkong")
        self.assertEqual(self.D.norm_region(""), "oss-cn-hongkong")
        self.assertEqual(self.D.norm_region(None), "oss-cn-hongkong")
        self.assertEqual(self.D.norm_region("  cn-beijing "), "oss-cn-beijing")

    def test_endpoint_of(self):
        self.assertEqual(self.D.endpoint_of("cn-hongkong"),
                         "https://oss-cn-hongkong.aliyuncs.com")

    def test_content_type_all_mapped(self):
        cases = {
            "a.html": "text/html; charset=utf-8",
            "a.htm": "text/html; charset=utf-8",
            "a.css": "text/css; charset=utf-8",
            "a.js": "application/javascript; charset=utf-8",
            "a.json": "application/json; charset=utf-8",
            "a.svg": "image/svg+xml",
            "a.png": "image/png",
            "a.woff2": "font/woff2",
            "a.pdf": "application/pdf",
            "a.weird": "application/octet-stream",
        }
        for path, ct in cases.items():
            self.assertEqual(self.D.content_type_for(path), ct, path)

    def test_content_type_case_insensitive(self):
        self.assertEqual(self.D.content_type_for("A.HTML"),
                         "text/html; charset=utf-8")

    def test_cache_control(self):
        for ext in (".html", ".htm", ".json", ".xml", ".txt"):
            self.assertEqual(self.D.cache_control_for("x" + ext), "no-cache")
        self.assertEqual(self.D.cache_control_for("x.css"),
                         "public, max-age=300")

    def test_md5(self):
        self.assertEqual(self.D.md5_of(b"hello"),
                         hashlib.md5(b"hello").hexdigest())

    def test_strip_proxy_snapshot(self):
        D = self.D
        # Windows 的 os.environ 键大小写不敏感（HTTP_PROXY 与 http_proxy 同一变量），
        # 所以只设大小写唯一的三组，别成对设置
        to_set = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]
        saved = {k: os.environ.get(k) for k in to_set}
        for k in to_set:
            os.environ[k] = "http://127.0.0.1:9999"
        try:
            D._SAVED_PROXY.clear()
            D.strip_proxy()
            for k in D.PROXY_KEYS:
                self.assertNotIn(k, os.environ)
            for k in to_set:
                self.assertEqual(D._SAVED_PROXY[k],
                                 "http://127.0.0.1:9999")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            D._SAVED_PROXY.clear()


class FakeNoSuchBucket(Exception):
    pass


class FakeBucket(object):
    def __init__(self, exists=True, acl="public-read", bpa=False):
        self.bucket_name = "fake-bucket"
        self._exists = exists
        self._acl = acl
        self._bpa = bpa
        self.created_with = None
        self.deleted_bpa = False
        self.objects = {}
        self.backups = []

    def get_bucket_info(self):
        if not self._exists:
            raise FakeNoSuchBucket()
        return {}

    def get_bucket_acl(self):
        m = mock.MagicMock()
        m.acl = self._acl
        return m

    def create_bucket(self, acl):
        self.created_with = acl
        self._exists = True
        return mock.MagicMock(status=200)

    def get_bucket_public_access_block(self):
        m = mock.MagicMock()
        m.block_public_access = self._bpa
        return m

    def delete_bucket_public_access_block(self):
        self.deleted_bpa = True
        self._bpa = False

    def head_object(self, key):
        if key not in self.objects:
            raise FakeNoSuchBucket()
        return mock.MagicMock()

    def get_object(self, key):
        m = mock.MagicMock()
        m.read.return_value = self.objects[key]
        return m

    def get_object_to_file(self, key, dest):
        open(dest, "wb").write(self.objects[key])
        self.backups.append(dest)


class TestEnsureBucket(unittest.TestCase):
    def setUp(self):
        import deploy_oss as D
        import oss2
        self.D = D
        self.oss2 = oss2

    def _run(self, b):
        # deploy_oss 的 oss2 是函数内延迟 import，patch 真实 oss2 模块的异常类
        with mock.patch.object(self.oss2.exceptions, "NoSuchBucket",
                               FakeNoSuchBucket):
            return self.D.ensure_bucket(b, "oss-cn-hongkong")

    def test_creates_when_missing(self):
        fb = FakeBucket(exists=False)
        self.assertTrue(self._run(fb))
        self.assertEqual(fb.created_with, self.oss2.BUCKET_ACL_PUBLIC_READ)

    def test_noop_when_exists(self):
        fb = FakeBucket(exists=True)
        self.assertFalse(self._run(fb))
        self.assertIsNone(fb.created_with)


class TestVerifyObject(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import deploy_oss as D
        cls.D = D

    def _args(self, expect=None):
        a = mock.MagicMock()
        a.expect = expect or []
        return a

    def test_md5_match(self):
        fb = FakeBucket()
        data = b"<html>esp32</html>"
        fb.objects["index.html"] = data
        local = os.path.join(tempfile.mkdtemp(), "index.html")
        open(local, "wb").write(data)
        self.assertTrue(self.D.verify_object(fb, "index.html", local, []))

    def test_md5_mismatch(self):
        fb = FakeBucket()
        fb.objects["index.html"] = b"remote"
        local = os.path.join(tempfile.mkdtemp(), "index.html")
        open(local, "wb").write(b"local")
        self.assertFalse(self.D.verify_object(fb, "index.html", local, []))

    def test_expect_all_hit(self):
        fb = FakeBucket()
        fb.objects["k"] = "alpha beta".encode()
        self.assertTrue(self.D.verify_object(fb, "k", None, ["alpha", "beta"]))

    def test_expect_partial_miss(self):
        fb = FakeBucket()
        fb.objects["k"] = b"alpha"
        self.assertFalse(
            self.D.verify_object(fb, "k", None, ["alpha", "gamma"]))

    def test_remote_missing_fails(self):
        fb = FakeBucket()
        self.assertFalse(self.D.verify_object(fb, "gone", None, []))


class TestBackupObject(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import deploy_oss as D
        cls.D = D

    def test_backup_written_with_md5_logged(self):
        fb = FakeBucket()
        data = b"old version content"
        fb.objects["index.html"] = data
        bdir = tempfile.mkdtemp()
        dest = self.D.backup_object(fb, "index.html", bdir)
        self.assertTrue(dest and os.path.exists(dest))
        self.assertEqual(open(dest, "rb").read(), data)
        self.assertIn(bdir, dest)

    def test_no_object_no_backup(self):
        fb = FakeBucket(exists=True)
        self.assertIsNone(self.D.backup_object(fb, "missing", None))


class TestVerifyPublic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import deploy_oss as D
        cls.D = D

    def _anon200(self, sess_cls):
        sess = mock.MagicMock()
        sess.get.return_value = _mk_resp({}, 200)
        sess_cls.return_value = sess
        return sess

    def test_bpa_off_passes_without_delete(self):
        fb = FakeBucket(bpa=False)
        with mock.patch("requests.Session") as S:
            self._anon200(S)
            self.assertTrue(self.D.verify_public(fb, "cn-hongkong"))
        self.assertFalse(fb.deleted_bpa)

    def test_bpa_on_gets_deleted_then_anon_200(self):
        fb = FakeBucket(bpa=True)
        with mock.patch("requests.Session") as S:
            self._anon200(S)
            self.assertTrue(self.D.verify_public(fb, "cn-hongkong"))
        self.assertTrue(fb.deleted_bpa)
        self.assertFalse(fb._bpa)

    def test_bpa_close_fail_returns_false(self):
        fb = FakeBucket(bpa=True)

        def stubborn():
            m = mock.MagicMock()
            m.block_public_access = True   # 删了仍是 True → 判失败
            return m

        fb.get_bucket_public_access_block = stubborn
        with mock.patch("requests.Session") as S:
            self._anon200(S)
            self.assertFalse(self.D.verify_public(fb, "cn-hongkong"))

    def test_anon_403_both_paths_fails(self):
        fb = FakeBucket(bpa=False)
        with mock.patch("requests.Session") as S:
            sess = mock.MagicMock()
            sess.get.return_value = _mk_resp({}, 403)
            S.return_value = sess
            self.assertFalse(self.D.verify_public(fb, "cn-hongkong"))


# ==================== A7. bind_domain 约定 ====================

class TestBindDomain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import bind_domain as B
        cls.B = B

    def test_norm_region(self):
        self.assertEqual(self.B.norm_region("cn-hongkong"),
                         "oss-cn-hongkong")
        self.assertEqual(self.B.norm_region("oss-cn-hongkong"),
                         "oss-cn-hongkong")

    def test_cert_object_force_is_string_true(self):
        c = self.B._Cert(28560188)
        self.assertIs(c.force, "true")     # 传 int 会 MalformedXML
        self.assertEqual(c.cert_id, "28560188")

    def test_cert_object_none_id(self):
        c = self.B._Cert(None)
        self.assertIsNone(c.cert_id)

    def test_wait_txt_normalizes_quotes_and_spaces(self):
        token = "abc_def-123"
        fake = mock.MagicMock()
        fake.stdout = '_dnsauth  TXT  " abc_def-123 " other'
        with mock.patch.object(self.B.subprocess, "run",
                               return_value=fake), \
             mock.patch("time.sleep"):
            self.assertTrue(self.B.wait_txt("x.example.com", token, tries=3))

    def test_wait_txt_never_matches(self):
        fake = mock.MagicMock()
        fake.stdout = "no such record"
        with mock.patch.object(self.B.subprocess, "run",
                               return_value=fake), \
             mock.patch("time.sleep"):
            self.assertFalse(self.B.wait_txt("x.example.com", "tok", tries=2))


# ==================== A8. 脚本语法自检 ====================

class TestScriptsCompile(unittest.TestCase):
    SCRIPTS = ["aliyun_rpc.py", "bind_domain.py", "deploy_oss.py",
               "cert_manager.py", "build_static.py", "verify_deploy.py",
               "set_github_secret.py"]

    def test_all_compile(self):
        for s in self.SCRIPTS:
            p = os.path.join(SCRIPTS, s)
            self.assertTrue(os.path.exists(p), "缺文件 %s" % s)
            with open(p, "rb") as f:
                src = f.read()
            compile(src, s, "exec")

    def test_no_broken_sdk_import(self):
        """坏 SDK 残留检测：任何脚本不得 import alibabacloud_*/tea/darabonba。"""
        banned = ("alibabacloud", "darabonba", "Tea.core")
        for s in self.SCRIPTS if hasattr(self, "SCRIPTS") else []:
            src = open(os.path.join(SCRIPTS, s), encoding="utf-8",
                       errors="ignore").read()
            for line in src.splitlines():
                if line.strip().startswith(("import", "from")):
                    for b in banned:
                        self.assertNotIn(b, line,
                                         "%s 引用了坏 SDK: %s" % (s, line))


# ==================== B. 在线只读冒烟（--live 才跑）====================

def _http_get(url):
    """先直连后代理（aliyuncs 系直连稳，站点走代理稳），任一 200 即返回响应。"""
    import requests
    last = None
    for trust in (True, False):
        try:
            s = requests.Session()
            s.trust_env = trust
            r = s.get(url, timeout=30)
            if r.status_code == 200:
                return r
            last = r
        except Exception as e:
            last = e
    raise last


@unittest.skipUnless(LIVE and os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID"),
                     "需要 --live 与真实 AK")
class TestLiveReadOnly(unittest.TestCase):
    """在线冒烟：全部只读，不做任何写操作。"""

    def test_01_dns_list(self):
        recs = R.dns_list(LIVE_ROOT)
        self.assertIsInstance(recs, list)
        print("  DNS %s: %d 条记录" % (LIVE_ROOT, len(recs)))

    def test_02_cas_list(self):
        certs = R.cas_list_certs("UPLOAD")
        self.assertIsInstance(certs, list)
        print("  CAS UPLOAD 证书: %d 张" % len(certs))

    def test_03_fc_list(self):
        doms = R.fc_list_custom_domains(LIVE_FC_REGION)
        self.assertIsInstance(doms, list)
        print("  FC %s: %s" % (LIVE_FC_REGION,
                               [d.get("domainName") for d in doms]))

    def test_04_oss_bucket_info(self):
        import oss2
        ak = os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"]
        sk = os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"]
        bk = oss2.Bucket(oss2.Auth(ak, sk),
                         "https://oss-cn-hongkong.aliyuncs.com", LIVE_BUCKET)
        info = bk.get_bucket_info()
        print("  OSS 桶 %s 存在" % LIVE_BUCKET)
        self.assertTrue(info)

    def test_05_site_https(self):
        r = _http_get(LIVE_SITE)
        self.assertEqual(r.status_code, 200)
        self.assertIn(LIVE_SITE_MARKER, r.text)
        print("  站点 %s -> 200 / %d 字节 / 标记命中" % (
            LIVE_SITE, len(r.content)))

    def test_06_fc_domain_cert_live(self):
        """FC 域名 HTTPS 实测（证书真实生效）。"""
        doms = [d.get("domainName") for d in
                R.fc_list_custom_domains(LIVE_FC_REGION)]
        target = next((d for d in doms
                       if d and d.endswith("." + LIVE_ROOT)), None)
        if not target:
            self.skipTest("FC 账号下无 *. %s 域名" % LIVE_ROOT)
        r = _http_get("https://%s/" % target)
        self.assertEqual(r.status_code, 200)
        print("  FC 域名 https://%s/ -> 200" % target)


if __name__ == "__main__":
    print("== aliyun-oss-static-deploy-skill 测试套件 ==")
    print("   在线冒烟: %s" % ("开" if LIVE else "关（加 --live 或 ALIYUN_LIVE=1 开启）"))
    unittest.main(verbosity=2)
