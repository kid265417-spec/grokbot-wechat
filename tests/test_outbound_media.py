"""Offline tests for outbound image/file sends and text-send regressions.
No WeChat, no webhook, no network. Run: python3 -m unittest discover -s tests -v
"""
import base64, hashlib, io, json, os, sys, tempfile, unittest, urllib.error
from contextlib import redirect_stderr, redirect_stdout

TMP = tempfile.mkdtemp(prefix="media-send-test-")
os.environ.setdefault("BRIDGE_DATA_DIR", TMP)
os.environ.setdefault("OWNER_NAME", "Tester")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ilink, media, media_send, outbox, send  # noqa: E402
from config import APP_PREFIX  # noqa: E402


def gif_bytes(frames):
    data = bytearray(b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff")
    if frames > 1:
        data += b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00"
    for _ in range(frames):
        data += b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00"
    data += b"\x3b"
    return bytes(data)


def webp_bytes(animated):
    flags = 0x02 if animated else 0x00
    payload = bytes([flags]) + b"\x00" * 9
    chunk = b"VP8X" + (10).to_bytes(4, "little") + payload
    body = b"WEBP" + chunk
    return b"RIFF" + len(body).to_bytes(4, "little") + body


def write_file(dirpath, name, data):
    path = os.path.join(dirpath, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


class FakeNet:
    def __init__(self):
        self.api = []
        self.cdn = []
        self.media_refuses_once = False
        self.media_timeout = False
        self.caption_timeout = False
        self.cdn_mode = "ok"
        self.upload_full_url = ""
        self.message_id = 9876543210123456789

    def api_post(self, endpoint, body, timeout):
        self.api.append((endpoint, json.loads(json.dumps(body))))
        if endpoint == "ilink/bot/getuploadurl":
            resp = {"ret": 0, "upload_param": "ab+cd/ef="}
            if self.upload_full_url:
                resp["upload_full_url"] = self.upload_full_url
            return json.dumps(resp)
        if endpoint == "ilink/bot/sendmessage":
            item = body["msg"]["item_list"][0]
            if item["type"] == 1 and self.caption_timeout:
                raise TimeoutError("caption timed out")
            if item["type"] != 1 and self.media_timeout:
                raise TimeoutError("media timed out")
            if item["type"] != 1 and self.media_refuses_once:
                self.media_refuses_once = False
                return json.dumps({"ret": 9, "errcode": 9, "errmsg": "window closed"})
            return json.dumps({"ret": 0, "errmsg": "", "message_id": self.message_id})
        raise AssertionError(endpoint)

    def cdn_post(self, url, ciphertext, timeout):
        self.cdn.append((url, ciphertext))
        if self.cdn_mode == "http400":
            raise media_send.CDNHTTPError(400, "bad request")
        if self.cdn_mode == "http503":
            raise media_send.CDNHTTPError(503, "unavailable")
        if self.cdn_mode == "flaky" and len(self.cdn) < 3:
            return {"status": 500, "encrypted_param": ""}
        if self.cdn_mode == "missing":
            return {"status": 200, "encrypted_param": ""}
        return {"status": 200, "encrypted_param": "DLPARAM"}


class TextRegressionTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.orig_queue = outbox.send_or_queue
        self.orig_send_text = outbox.send_text
        self.orig_post = ilink.post
        self.orig_sleep = outbox.time.sleep

    def tearDown(self):
        outbox.send_or_queue = self.orig_queue
        outbox.send_text = self.orig_send_text
        ilink.post = self.orig_post
        outbox.time.sleep = self.orig_sleep

    def _queue(self, ok, resp):
        def fake(text, to=None, context_token=None):
            self.calls.append((text, to, context_token))
            return ok, resp
        outbox.send_or_queue = fake

    def test_text_sent_stdout_and_args(self):
        self._queue(True, "{}")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = send.main(["hello", "--to", "user@im.wechat", "--no-context"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.calls, [("hello", "user@im.wechat", "")])
        self.assertTrue(buf.getvalue().startswith("sent:"))
        self.assertNotIn("MEDIA_RESULT", buf.getvalue())

    def test_text_app_prefix_and_default_context(self):
        self._queue(True, "{}")
        with redirect_stdout(io.StringIO()):
            rc = send.main(["hello", "--app"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.calls, [(APP_PREFIX + "hello", None, None)])

    def test_text_queues_with_exit_3(self):
        self._queue(False, '{"ret": 1}')
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = send.main(["hello"])
        self.assertEqual(rc, 3)
        self.assertTrue(buf.getvalue().startswith("QUEUED (will auto-send when the user next writes):"))

    def test_text_superseded_sends_nothing(self):
        self._queue(True, "{}")
        ilink.save_state({"last_inbound_ms": 10_000})
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = send.main(["hello", "--reply-to-ms", "1000"])
        self.assertEqual(rc, 4)
        self.assertEqual(self.calls, [])
        self.assertIn("SUPERSEDED:", buf.getvalue())

    def test_text_does_not_call_media_send(self):
        self._queue(True, "{}")
        called = []
        orig = media_send.send_path
        media_send.send_path = lambda *a, **k: called.append(1)
        try:
            with redirect_stdout(io.StringIO()):
                send.main(["hello"])
        finally:
            media_send.send_path = orig
        self.assertEqual(called, [])

    def test_send_text_payload_unchanged(self):
        captured = {}
        def fake_post(endpoint, body, timeout=15):
            captured["endpoint"] = endpoint
            captured["body"] = body
            return "{}"
        ilink.post = fake_post
        os.makedirs(os.path.dirname(ilink.CRED), exist_ok=True)
        with open(ilink.CRED, "w") as f:
            json.dump({"bot_token": "test-token", "ilink_user_id": "binder@im.wechat"}, f)
        os.chmod(ilink.CRED, 0o600)
        ilink.save_state({"last_from_user_id": "user@im.wechat",
                          "context_tokens": {"user@im.wechat": "CTX"}})
        resp, has_ctx = ilink.send_text("hello")
        self.assertEqual(resp, "{}")
        self.assertTrue(has_ctx)
        self.assertEqual(captured["endpoint"], "ilink/bot/sendmessage")
        msg = captured["body"]["msg"]
        self.assertEqual(msg["from_user_id"], "")
        self.assertEqual(msg["to_user_id"], "user@im.wechat")
        self.assertEqual(msg["message_type"], 2)
        self.assertEqual(msg["message_state"], 2)
        self.assertEqual(msg["context_token"], "CTX")
        self.assertEqual(msg["item_list"], [{"type": 1, "text_item": {"text": "hello"}}])
        self.assertTrue(msg["client_id"].startswith("openclaw-weixin-"))
        self.assertNotIn("base_info", captured["body"])

    def test_outbox_failure_still_queues_text(self):
        if os.path.exists(outbox.OUTBOX):
            os.remove(outbox.OUTBOX)
        def boom(text, **kw):
            raise TimeoutError("down")
        outbox.send_text = boom
        sent, resp = outbox.send_or_queue("hello", to="U")
        self.assertFalse(sent)
        self.assertIn("TimeoutError", resp)
        queued = json.load(open(outbox.OUTBOX))
        self.assertEqual(queued[0]["text"], "hello")
        self.assertEqual(queued[0]["to"], "U")
        os.remove(outbox.OUTBOX)

    def test_flush_still_calls_send_text(self):
        outbox._save([{"text": "queued-text", "to": "U", "queued_at": 1}])
        seen = []
        def fake(text, to=None, context_token=None):
            seen.append((text, to, context_token))
            return "{}", True
        outbox.send_text = fake
        outbox.time.sleep = lambda s: None
        n = outbox.flush()
        self.assertEqual(n, 1)
        self.assertEqual(seen, [("queued-text", "U", "")])


class FormatAndCryptoTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="media-files-")
        self.journal = tempfile.mkdtemp(prefix="media-journal-")

    def test_magic_and_animation_metadata(self):
        png = write_file(self.dir, "a.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
        jpg = write_file(self.dir, "a.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 16)
        gif1 = write_file(self.dir, "still.gif", gif_bytes(1))
        gif2 = write_file(self.dir, "move.gif", gif_bytes(2))
        webp = write_file(self.dir, "a.webp", webp_bytes(True))
        still_webp = write_file(self.dir, "b.webp", webp_bytes(False))
        self.assertEqual(media_send.load_media(png, "image")["format"], "png")
        self.assertFalse(media_send.load_media(png, "image")["animated"])
        self.assertEqual(media_send.load_media(jpg, "image")["format"], "jpeg")
        self.assertFalse(media_send.load_media(jpg, "image")["animated"])
        still = media_send.load_media(gif1, "image")
        self.assertEqual(still["frame_count"], 1)
        self.assertFalse(still["animated"])
        anim = media_send.load_media(gif2, "image")
        self.assertEqual(anim["frame_count"], 2)
        self.assertTrue(anim["animated"])
        self.assertEqual(anim["conversion"], "none")
        self.assertTrue(media_send.load_media(webp, "image")["animated"])
        self.assertFalse(media_send.load_media(still_webp, "image")["animated"])

    def test_rejects_mismatched_or_empty_or_secret(self):
        bad = write_file(self.dir, "a.jpg", b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
        with self.assertRaises(media_send.LocalError):
            media_send.load_media(bad, "image")
        empty = write_file(self.dir, "a.png", b"")
        with self.assertRaises(media_send.LocalError):
            media_send.load_media(empty, "image")
        secret = write_file(self.dir, "credentials.json", b"%PDF-1.4\n")
        with self.assertRaises(media_send.LocalError):
            media_send.load_media(secret, "file")
        pdf_as_zip = write_file(self.dir, "a.zip", b"%PDF-1.4\n")
        with self.assertRaises(media_send.LocalError):
            media_send.load_media(pdf_as_zip, "file")
        os.environ["WECHAT_MEDIA_MAX_BYTES"] = "32"
        try:
            big = write_file(self.dir, "big.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
            with self.assertRaises(media_send.LocalError):
                media_send.load_media(big, "image")
        finally:
            del os.environ["WECHAT_MEDIA_MAX_BYTES"]

    def test_file_magics(self):
        pdf = write_file(self.dir, "a.pdf", b"%PDF-1.7\n%")
        doc = write_file(self.dir, "a.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8)
        docx = write_file(self.dir, "a.docx", b"PK\x03\x04" + b"\x00" * 8)
        zf = write_file(self.dir, "a.zip", b"PK\x03\x04" + b"\x00" * 8)
        txt = write_file(self.dir, "notes.txt", b"hello file")
        self.assertEqual(media_send.load_media(pdf, "file")["format"], "pdf")
        self.assertEqual(media_send.load_media(doc, "file")["format"], "doc")
        self.assertEqual(media_send.load_media(docx, "file")["format"], "docx")
        self.assertEqual(media_send.load_media(zf, "file")["format"], "zip")
        self.assertEqual(media_send.load_media(txt, "file")["format"], "txt")

    def test_encrypt_roundtrip_matches_inbound_decrypt(self):
        key = bytes(range(16))
        data = gif_bytes(2)
        ct = media_send.encrypt_aes128_ecb(data, key)
        self.assertEqual(len(ct), media_send.padded_size(len(data)))
        self.assertEqual(media.decrypt(ct, key), data)
        self.assertEqual(base64.b64decode(media_send.aes_key_b64(key)), key.hex().encode())
        self.assertNotEqual(media_send.aes_key_b64(key), base64.b64encode(key).decode())
        self.assertEqual(media.parse_key({"media": {"aes_key": media_send.aes_key_b64(key)}}), key)

    def test_upload_url_encoding_and_host_guard(self):
        url = media_send.build_upload_url("", "ab+cd/ef=", "aabb")
        self.assertTrue(url.startswith("https://novac2c.cdn.weixin.qq.com/c2c/upload?"))
        self.assertIn("encrypted_query_param=ab%2Bcd%2Fef%3D", url)
        self.assertIn("filekey=aabb", url)
        self.assertFalse(media_send.upload_url_allowed("http://novac2c.cdn.weixin.qq.com/c2c/upload"))
        self.assertFalse(media_send.upload_url_allowed("https://evil.example/upload"))
        self.assertTrue(media_send.upload_url_allowed("https://novac2c.cdn.weixin.qq.com/c2c/upload?x=1"))


class SendOutcomeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="media-out-")
        self.journal = tempfile.mkdtemp(prefix="media-j-")
        self.hist = os.path.join(self.dir, "history.log")
        self.net = FakeNet()
        self.png = write_file(self.dir, "pic.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
        self.gif = write_file(self.dir, "anim.gif", gif_bytes(2))
        self.pdf = write_file(self.dir, "note.pdf", b"%PDF-1.4\nhello")
        self.txt = write_file(self.dir, "note.txt", b"small file")

    def send(self, path, kind, **kw):
        kw.setdefault("to", "user@im.wechat")
        kw.setdefault("context_token", "CTX")
        kw.setdefault("journal_dir", self.journal)
        kw.setdefault("transport", self.net)
        kw.setdefault("history_path", self.hist)
        return media_send.send_path(path, kind, **kw)

    def test_image_success_is_acceptance_not_delivery(self):
        result = self.send(self.gif, "image", caption="看图")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["status"], "API_ACCEPTED")
        self.assertTrue(result["api_accepted"])
        self.assertIsNone(result["recipient_delivered"])
        self.assertFalse(result["recipient_delivery_known"])
        self.assertIsNone(result["read_receipt"])
        self.assertFalse(result["read_receipt_supported"])
        self.assertEqual(result["server_message_id"], "9876543210123456789")
        self.assertTrue(result["client_id"].startswith("openclaw-weixin-"))
        self.assertTrue(result["animated"])
        self.assertEqual(result["frame_count"], 2)
        self.assertEqual(result["conversion"], "none")
        self.assertEqual([ep for ep, _ in self.net.api],
                         ["ilink/bot/sendmessage", "ilink/bot/getuploadurl", "ilink/bot/sendmessage"])
        upload = self.net.api[1]
        body = upload[1]
        raw = open(self.gif, "rb").read()
        self.assertEqual(body["media_type"], 1)
        self.assertTrue(body["no_need_thumb"])
        self.assertEqual(body["rawsize"], len(raw))
        self.assertEqual(body["rawfilemd5"], hashlib.md5(raw, usedforsecurity=False).hexdigest())
        self.assertEqual(body["to_user_id"], "user@im.wechat")
        self.assertEqual(len(body["filekey"]), 32)
        self.assertEqual(len(body["aeskey"]), 32)
        ct = self.net.cdn[0][1]
        self.assertEqual(body["filesize"], len(ct))
        self.assertEqual(media.decrypt(ct, bytes.fromhex(body["aeskey"])), raw)
        self.assertIn("encrypted_query_param=ab%2Bcd%2Fef%3D", self.net.cdn[0][0])
        caption = self.net.api[0][1]["msg"]
        image = self.net.api[2][1]["msg"]
        self.assertEqual(caption["item_list"][0]["type"], 1)
        self.assertEqual(caption["item_list"][0]["text_item"]["text"], "看图")
        self.assertEqual(caption["context_token"], "CTX")
        item = image["item_list"][0]
        self.assertEqual(item["type"], 2)
        self.assertNotIn("thumb_media", item["image_item"])
        self.assertEqual(item["image_item"]["mid_size"], len(ct))
        self.assertEqual(item["image_item"]["media"]["encrypt_type"], 1)
        self.assertEqual(item["image_item"]["media"]["encrypt_query_param"], "DLPARAM")
        self.assertEqual(item["image_item"]["media"]["aes_key"], media_send.aes_key_b64(bytes.fromhex(body["aeskey"])))
        self.assertNotEqual(item["image_item"]["media"]["aes_key"], base64.b64encode(bytes.fromhex(body["aeskey"])).decode())
        text = open(self.hist, encoding="utf-8").read()
        self.assertIn("看图", text)
        self.assertIn("anim.gif", text)
        journal = open(os.path.join(self.journal, "media_send_journal.json"), encoding="utf-8").read()
        self.assertNotIn("DLPARAM", journal)
        self.assertNotIn(body["aeskey"], journal)

    def test_file_payload_and_context_omitted_when_empty(self):
        result = self.send(self.pdf, "file", context_token="")
        self.assertEqual(result["status"], "API_ACCEPTED")
        self.assertEqual(self.net.api[0][1]["media_type"], 3)
        msg = self.net.api[1][1]["msg"]
        self.assertNotIn("context_token", msg)
        item = msg["item_list"][0]
        self.assertEqual(item["type"], 4)
        self.assertEqual(item["file_item"]["file_name"], "note.pdf")
        self.assertEqual(item["file_item"]["len"], str(os.path.getsize(self.pdf)))
        self.assertIsInstance(item["file_item"]["len"], str)
        self.assertNotIn("md5", item["file_item"])

    def test_general_file_and_explicit_refusal_can_be_retried(self):
        self.net.media_refuses_once = True
        refused = self.send(self.txt, "file")
        self.assertEqual(refused["exit_code"], 5)
        self.assertFalse(refused["api_accepted"])
        self.assertTrue(refused["safe_to_retry"])
        self.assertIsNone(refused["recipient_delivered"])
        again = self.send(self.txt, "file")
        self.assertEqual(again["status"], "API_ACCEPTED")
        self.assertFalse(again["recipient_delivery_known"])

    def test_caption_refusal_does_not_upload(self):
        def refuse_caption(endpoint, body, timeout):
            self.net.api.append((endpoint, body))
            if endpoint == "ilink/bot/sendmessage":
                return json.dumps({"ret": 4, "errmsg": "no"})
            raise AssertionError(endpoint)
        self.net.api_post = refuse_caption
        result = self.send(self.png, "image", caption="nope")
        self.assertEqual(result["exit_code"], 5)
        self.assertEqual(result["caption_status"], "rejected")
        self.assertEqual(self.net.cdn, [])
        self.assertFalse(os.path.exists(self.hist))

    def test_uncertain_send_is_not_retried_until_confirmed(self):
        self.net.media_timeout = True
        first = self.send(self.png, "image")
        self.assertEqual(first["exit_code"], 6)
        self.assertEqual(first["status"], "UNCERTAIN")
        self.assertIsNone(first["api_accepted"])
        self.assertFalse(first["safe_to_retry"])
        self.assertFalse(first["recipient_delivery_known"])
        calls = len(self.net.api)
        blocked = self.send(self.png, "image")
        self.assertEqual(blocked["status"], "BLOCKED")
        self.assertEqual(blocked["exit_code"], 6)
        self.assertEqual(len(self.net.api), calls)
        self.net.media_timeout = False
        retried = self.send(self.png, "image", confirm_resend=True, client_id=first["client_id"])
        self.assertEqual(retried["status"], "API_ACCEPTED")
        self.assertEqual(retried["client_id"], first["client_id"])
        sent_ids = [call[1]["msg"]["client_id"] for call in self.net.api if call[0] == "ilink/bot/sendmessage"]
        self.assertEqual(sent_ids[-1], first["client_id"])

    def test_uncertain_caption_does_not_upload_or_send_file(self):
        self.net.caption_timeout = True
        result = self.send(self.pdf, "file", caption="说明")
        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(self.net.cdn, [])
        self.assertEqual(sum(1 for ep, _ in self.net.api if ep == "ilink/bot/sendmessage"), 1)

    def test_accepted_caption_is_not_repeated_after_media_refusal(self):
        self.net.media_refuses_once = True
        first = self.send(self.png, "image", caption="只发一次")
        self.assertEqual(first["caption_status"], "accepted")
        self.assertEqual(first["status"], "REJECTED")
        second = self.send(self.png, "image", caption="只发一次")
        self.assertEqual(second["status"], "API_ACCEPTED")
        self.assertEqual(second["caption_status"], "skipped")
        texts = [call[1]["msg"]["item_list"][0] for call in self.net.api if call[0] == "ilink/bot/sendmessage"]
        captions = [it for it in texts if it["type"] == 1]
        self.assertEqual(len(captions), 1)

    def test_cdn_4xx_does_not_retry_or_send(self):
        self.net.cdn_mode = "http400"
        result = self.send(self.pdf, "file")
        self.assertEqual(result["exit_code"], 5)
        self.assertTrue(result["safe_to_retry"])
        self.assertEqual(len(self.net.cdn), 1)
        self.assertFalse(any(ep == "ilink/bot/sendmessage" for ep, _ in self.net.api))

    def test_cdn_5xx_retries_then_stops_before_send(self):
        self.net.cdn_mode = "http503"
        result = self.send(self.pdf, "file")
        self.assertEqual(result["exit_code"], 5)
        self.assertEqual(len(self.net.cdn), 3)
        self.assertFalse(any(ep == "ilink/bot/sendmessage" for ep, _ in self.net.api))

    def test_cdn_flaky_then_success(self):
        self.net.cdn_mode = "flaky"
        result = self.send(self.txt, "file")
        self.assertEqual(result["status"], "API_ACCEPTED")
        self.assertEqual(len(self.net.cdn), 3)

    def test_evil_upload_url_is_not_posted(self):
        self.net.upload_full_url = "https://evil.example/upload"
        result = self.send(self.txt, "file")
        self.assertEqual(result["exit_code"], 5)
        self.assertEqual(self.net.cdn, [])
        self.assertIn("documented CDN", result["note"])

    def test_cli_media_superseded_and_acceptance_line(self):
        ilink.save_state({"last_inbound_ms": 10_000})
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = send.main(["--image", self.png, "--reply-to-ms", "1000"])
        self.assertEqual(rc, 4)
        self.assertIn("SUPERSEDED:", buf.getvalue())
        self.assertEqual(self.net.api, [])

    def test_cli_prints_acceptance_distinct_from_delivery(self):
        orig = media_send.send_path
        def fake(path, kind, **kw):
            return media_send._public_result(
                status="API_ACCEPTED", exit_code=0, api_accepted=True, kind=kind, format="png",
                conversion="none", bytes=3, file_name="pic.png", client_id="openclaw-weixin-cli",
                server_message_id="55", note="api only")
        media_send.send_path = fake
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = send.main(["--image", self.png, "--caption", "hi", "--no-context"])
        finally:
            media_send.send_path = orig
        self.assertEqual(rc, 0)
        text = buf.getvalue()
        self.assertIn("recipient_delivered: unknown", text)
        self.assertIn("read_receipt: not_provided_by_ilink_sendmessage", text)
        self.assertIn('"api_accepted": true', text)
        self.assertIn('"recipient_delivery_known": false', text)
        self.assertIn('"read_receipt_supported": false', text)

    def test_cli_rejects_text_mixed_with_image(self):
        err = io.StringIO()
        with redirect_stderr(err):
            rc = send.main(["hello", "--image", self.png])
        self.assertEqual(rc, 2)
        self.assertIn("caption", err.getvalue())

    def test_local_reject_does_not_touch_journal(self):
        missing = os.path.join(self.dir, "nope.png")
        result = self.send(missing, "image")
        self.assertEqual(result["exit_code"], 2)
        self.assertFalse(os.path.exists(os.path.join(self.journal, "media_send_journal.json")))

    def test_media_send_does_not_write_text_outbox(self):
        if os.path.exists(outbox.OUTBOX):
            os.remove(outbox.OUTBOX)
        result = self.send(self.pdf, "file")
        self.assertEqual(result["status"], "API_ACCEPTED")
        self.assertFalse(os.path.exists(outbox.OUTBOX))

    def test_cdn_transport_posts_ciphertext_and_reads_header(self):
        captured = {}
        class Headers:
            def get(self, key, default=None):
                if key.lower() == "x-encrypted-param":
                    return "HDR"
                return default
        class Resp:
            status = 200
            headers = Headers()
            def __enter__(self): return self
            def __exit__(self, *a): return False
        def urlopen(req, timeout=0):
            captured["method"] = req.get_method()
            captured["header"] = req.get_header("Content-type")
            captured["data"] = req.data
            captured["url"] = req.full_url
            return Resp()
        orig = urllib.request.urlopen
        urllib.request.urlopen = urlopen
        try:
            out = media_send.IlinkTransport().cdn_post(
                "https://novac2c.cdn.weixin.qq.com/c2c/upload?encrypted_query_param=aa", b"cipher", 30)
        finally:
            urllib.request.urlopen = orig
        self.assertEqual(out["encrypted_param"], "HDR")
        self.assertEqual(captured["method"], "POST")
        self.assertIn("octet-stream", captured["header"])
        self.assertEqual(captured["data"], b"cipher")


if __name__ == "__main__":
    unittest.main()
