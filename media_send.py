"""Outbound WeChat iLink image and file sends.

This module does not change text send, receive, forwarding, or the keep-alive nudge.
`ilink.send_text` and `outbox.send_or_queue` stay the text path.

Protocol (public client + reference, not a private API):
- https://github.com/Tencent/openclaw-weixin/blob/main/docs/protocol.md
- https://github.com/Tencent/openclaw-weixin/blob/main/src/cdn/upload.ts
- https://github.com/Tencent/openclaw-weixin/blob/main/src/cdn/cdn-upload.ts
- https://github.com/Tencent/openclaw-weixin/blob/main/src/cdn/cdn-url.ts
- https://github.com/Tencent/openclaw-weixin/blob/main/src/cdn/aes-ecb.ts
- https://github.com/Tencent/openclaw-weixin/blob/main/src/messaging/send.ts
- https://github.com/Tencent/openclaw-weixin/blob/main/src/api/types.ts
The 2026 chihao.li write-up only documents text/voice and is stale for media:
https://www.chihao.li/blog/en/wechat-clawbot-ilink-protocol/

Wire facts used here:
- POST ilink/bot/getuploadurl with media_type 1 (image) or 3 (file), plaintext
  size + MD5, AES-128-ECB PKCS#7 ciphertext size, no_need_thumb true, aeskey hex.
- POST the ciphertext to upload_full_url, or else
  https://novac2c.cdn.weixin.qq.com/c2c/upload?encrypted_query_param=&filekey=
  Content-Type application/octet-stream. Success is HTTP 200 and a nonempty
  x-encrypted-param header. HTTP 4xx is not retried; other upload failures are
  tried up to 3 times (official cdn-upload.ts).
- POST ilink/bot/sendmessage with one item. Image: type 2, media.encrypt_type 1,
  media.aes_key = base64(hex string of the 16-byte key), mid_size = ciphertext
  length. File: type 4, same media object, file_name, len = decimal plaintext size.
- sendmessage JSON may include ret, errcode, errmsg, and message_id. ret 0 (or an
  empty object) means the API accepted the request. The documented response has
  no delivery or read-receipt field. Acceptance is not proof the WeChat client
  showed the file. See https://github.com/Tencent/openclaw-weixin/issues/278

Image bytes are encrypted as-is. There is no transcode, no thumbnail, and no
animation flatten step in the official upload pipeline (no_need_thumb is always
true). GIF/WEBP animation therefore survives *this* sender. Whether the WeChat
bubble plays that animation is not specified by the protocol. Public inbound
reports show image messages can be recompressed by WeChat, while file_item bytes
were stored without a second encode (openclaw-weixin issue 241). Use --file when
the original container must be preserved.

The protocol reference does not publish a maximum upload size. DEFAULT_MAX_BYTES
is a local guard, not an iLink limit.
"""
import base64, hashlib, json, os, secrets, time, urllib.error, urllib.parse, urllib.request
import fcntl
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import config, history, ilink

CDN_BASE = "https://novac2c.cdn.weixin.qq.com/c2c"
CDN_UPLOAD_ATTEMPTS = 3
# Local guards. docs/protocol.md defines rawsize/filesize but no maximum.
DEFAULT_MAX_BYTES = 20 * 1024 * 1024
HARD_MAX_BYTES = 100 * 1024 * 1024
JOURNAL_NAME = "media_send_journal.json"
UNRESOLVED = {"sending_caption", "sending_media", "uncertain"}
SECRET_BASENAMES = {
    "credentials.json", ".env", "state.json", "outbox.json", "pending.json",
    "forward_seen.json", "history.log", "verify_code.txt", "media_send_journal.json",
}
IMAGE_EXT = {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif", ".webp": "webp"}

class LocalError(Exception):
    pass

def max_bytes():
    raw = os.environ.get("WECHAT_MEDIA_MAX_BYTES", "").strip()
    if not raw:
        return DEFAULT_MAX_BYTES
    try:
        n = int(raw)
    except ValueError:
        raise LocalError("WECHAT_MEDIA_MAX_BYTES must be an integer")
    if n < 1 or n > HARD_MAX_BYTES:
        raise LocalError("WECHAT_MEDIA_MAX_BYTES must be between 1 and %d" % HARD_MAX_BYTES)
    return n

def padded_size(n):
    """AES-128-ECB PKCS#7 ciphertext length. Matches aes-ecb.ts aesEcbPaddedSize."""
    return ((n + 1 + 15) // 16) * 16

def encrypt_aes128_ecb(plaintext, key):
    if len(key) != 16:
        raise LocalError("AES key must be 16 bytes")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(padded) + enc.finalize()

def aes_key_b64(key):
    """Official sender: base64 of the hex ASCII key, not base64 of the raw 16 bytes."""
    return base64.b64encode(key.hex().encode("ascii")).decode("ascii")

def encode_uri_component(s):
    """Match JS encodeURIComponent used by cdn-url.ts."""
    return urllib.parse.quote(s, safe="-_.!~*'()")

def build_upload_url(upload_full_url, upload_param, filekey):
    full = (upload_full_url or "").strip()
    if full:
        return full
    if not upload_param:
        raise LocalError("getuploadurl returned neither upload_full_url nor upload_param")
    return "%s/upload?encrypted_query_param=%s&filekey=%s" % (
        CDN_BASE, encode_uri_component(upload_param), encode_uri_component(filekey))

def upload_url_allowed(url):
    p = urllib.parse.urlparse(url)
    host = (p.hostname or "").lower()
    if p.scheme != "https" or p.username or p.password:
        return False
    if p.port not in (None, 443):
        return False
    if host != "novac2c.cdn.weixin.qq.com" and not host.endswith(".cdn.weixin.qq.com"):
        return False
    return True

def sniff_image(data):
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    return None

def _skip_subblocks(data, i):
    while i < len(data):
        n = data[i]
        i += 1
        if n == 0:
            return i
        i += n
    return i

def gif_frame_count(data):
    """Best-effort GIF image-descriptor count. None if the container can't be walked.
    Does not decode or rewrite pixels."""
    if len(data) < 13 or not data.startswith((b"GIF87a", b"GIF89a")):
        return None
    i = 13
    if data[10] & 0x80:
        i += 3 * (2 << (data[10] & 0x07))
    if i > len(data):
        return None
    frames = 0
    while i < len(data):
        b = data[i]
        if b == 0x3B:
            return frames
        if b == 0x2C:
            if i + 10 > len(data):
                return None
            ipacked = data[i + 9]
            i += 10
            if ipacked & 0x80:
                i += 3 * (2 << (ipacked & 0x07))
            if i >= len(data):
                return None
            i += 1
            i = _skip_subblocks(data, i)
            frames += 1
        elif b == 0x21:
            if i + 2 > len(data):
                return None
            i += 2
            i = _skip_subblocks(data, i)
        else:
            return None
    return frames

def webp_animated(data):
    """True/False from VP8X animation bit or an ANIM chunk. None if not walkable."""
    if len(data) < 12 or not data.startswith(b"RIFF") or data[8:12] != b"WEBP":
        return None
    i = 12
    seen = False
    while i + 8 <= len(data):
        tag = data[i:i + 4]
        size = int.from_bytes(data[i + 4:i + 8], "little")
        payload = data[i + 8:i + 8 + size]
        if tag == b"ANIM":
            return True
        if tag == b"VP8X" and payload:
            return bool(payload[0] & 0x02)
        seen = True
        i += 8 + size + (size & 1)
    return False if seen else None

def _zip_magic(data):
    return data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))

def _secret_path(path):
    real = os.path.realpath(path)
    if os.path.basename(real).lower() in SECRET_BASENAMES:
        return True
    protected = []
    for root in (config.DATA_DIR, config.CODE_DIR):
        for name in SECRET_BASENAMES:
            protected.append(os.path.realpath(os.path.join(root, name)))
    return real in protected

def _safe_filename(name):
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
        raise LocalError("unsafe file name")
    if any(ord(ch) < 32 for ch in name):
        raise LocalError("file name contains control characters")
    if len(name) > 180:
        raise LocalError("file name longer than 180 characters")
    if name.lower() in SECRET_BASENAMES:
        raise LocalError("refusing to send a credential or runtime file")
    return name

def load_media(path, kind):
    if kind not in ("image", "file"):
        raise LocalError("kind must be image or file")
    if not path or not os.path.isfile(path):
        raise LocalError("path is not a regular file")
    if _secret_path(path):
        raise LocalError("refusing to send credentials, .env, or runtime state")
    name = _safe_filename(os.path.basename(path))
    limit = max_bytes()
    size = os.path.getsize(path)
    if size <= 0:
        raise LocalError("file is empty")
    if size > limit:
        raise LocalError("file is %d bytes; local guard is %d (protocol publishes no maximum; set WECHAT_MEDIA_MAX_BYTES)" % (size, limit))
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != size:
        raise LocalError("file changed while reading; nothing sent")
    if len(data) > limit:
        raise LocalError("file exceeds local size guard; nothing sent")
    ext = os.path.splitext(name)[1].lower()
    info = {"path": os.path.abspath(path), "file_name": name, "ext": ext, "data": data,
            "format": None, "animated": None, "frame_count": None, "conversion": "none"}
    if kind == "image":
        expect = IMAGE_EXT.get(ext)
        if not expect:
            raise LocalError("image send accepts .jpg .jpeg .png .gif .webp only")
        got = sniff_image(data)
        if got != expect:
            raise LocalError("image contents do not match %s" % ext)
        if expect == "gif" and len(data) < 13:
            raise LocalError("gif header is truncated")
        if expect == "webp" and len(data) < 12:
            raise LocalError("webp header is truncated")
        info["format"] = expect
        if expect == "gif":
            frames = gif_frame_count(data)
            info["frame_count"] = frames
            info["animated"] = None if frames is None else frames >= 2
        elif expect == "webp":
            info["animated"] = webp_animated(data)
        else:
            info["animated"] = False
    else:
        if ext == ".pdf":
            if not data.startswith(b"%PDF-"):
                raise LocalError("pdf contents do not start with %PDF-")
            info["format"] = "pdf"
        elif ext == ".zip":
            if not _zip_magic(data):
                raise LocalError("zip contents do not start with a PK header")
            info["format"] = "zip"
        elif ext == ".doc":
            if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                raise LocalError("doc contents are not an OLE compound document")
            info["format"] = "doc"
        elif ext == ".docx":
            if not data.startswith(b"PK\x03\x04"):
                raise LocalError("docx contents are not a zip package")
            info["format"] = "docx"
        else:
            info["format"] = ext[1:] if ext else "bin"
    info["sha256"] = hashlib.sha256(data).hexdigest()
    info["rawfilemd5"] = hashlib.md5(data, usedforsecurity=False).hexdigest()
    return info

def resolve_recipient(to, context_token):
    """Same lookup as ilink.send_text. Does not modify that function.
    Credentials and state are read only when --to or the context token was omitted."""
    if to and context_token is not None:
        return to, context_token
    st = ilink.load_state()
    if not to:
        c = ilink.creds()
        to = st.get("last_from_user_id") or c.get("ilink_user_id")
    if not to:
        raise LocalError("no recipient (pass --to, or receive one message first)")
    if context_token is None:
        context_token = (st.get("context_tokens") or {}).get(to) or ""
    return to, context_token

def build_send_body(to, client_id, item, context_token):
    msg = {"from_user_id": "", "to_user_id": to, "client_id": client_id,
           "message_type": 2, "message_state": 2, "item_list": [item]}
    if context_token:
        msg["context_token"] = context_token
    return {"msg": msg}

def build_text_item(text):
    return {"type": 1, "text_item": {"text": text}}

def build_media_ref(download_param, key):
    return {"encrypt_query_param": download_param, "aes_key": aes_key_b64(key), "encrypt_type": 1}

def build_image_item(download_param, key, ciphertext_len):
    return {"type": 2, "image_item": {"media": build_media_ref(download_param, key), "mid_size": ciphertext_len}}

def build_file_item(download_param, key, file_name, plaintext_len):
    return {"type": 4, "file_item": {
        "media": build_media_ref(download_param, key),
        "file_name": file_name, "len": str(plaintext_len)}}

def build_upload_body(filekey, media_type, to, rawsize, rawfilemd5, filesize, aeskey_hex):
    return {"filekey": filekey, "media_type": media_type, "to_user_id": to,
            "rawsize": rawsize, "rawfilemd5": rawfilemd5, "filesize": filesize,
            "no_need_thumb": True, "aeskey": aeskey_hex}

def new_client_id():
    return "openclaw-weixin-" + secrets.token_hex(8)

def _check_client_id(client_id):
    if client_id is None:
        return None
    if not isinstance(client_id, str) or len(client_id) < 8 or len(client_id) > 80:
        raise LocalError("invalid --client-id")
    if any(not (ch.isalnum() or ch in "._:-") for ch in client_id):
        raise LocalError("invalid --client-id")
    return client_id

def api_ok(resp_text):
    """Same acceptance rule as outbox.is_ok. None means the body is not a JSON object."""
    try:
        r = json.loads(resp_text) if str(resp_text).strip() else {}
    except ValueError:
        return None, {}
    if not isinstance(r, dict):
        return None, {}
    if r.get("ret") or r.get("errcode"):
        return False, r
    return True, r

def server_message_id(obj):
    if not isinstance(obj, dict):
        return None
    for k in ("message_id", "msg_id"):
        if obj.get(k) not in (None, ""):
            return str(obj.get(k))
    return None

class CDNHTTPError(Exception):
    def __init__(self, status, detail):
        self.status = status
        self.detail = detail
        super().__init__("cdn http %s" % status)

class IlinkTransport:
    def api_post(self, endpoint, body, timeout):
        return ilink.post(endpoint, body, timeout=timeout)

    def cdn_post(self, url, ciphertext, timeout):
        if not upload_url_allowed(url):
            raise LocalError("refusing CDN upload URL outside the documented WeChat CDN host")
        req = urllib.request.Request(url, data=ciphertext, method="POST",
                                     headers={"Content-Type": "application/octet-stream"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as f:
                return {"status": getattr(f, "status", 200),
                        "encrypted_param": f.headers.get("x-encrypted-param") or ""}
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read(180).decode("utf-8", "replace")
            except Exception:
                pass
            raise CDNHTTPError(e.code, detail)

def _journal_path(journal_dir):
    return os.path.join(journal_dir, JOURNAL_NAME)

def _cap(records, limit=200):
    if len(records) <= limit:
        return records
    resolved = [i for i, r in enumerate(records) if r.get("stage") not in UNRESOLVED]
    drop_n = len(records) - limit
    drop = set(resolved[:drop_n])
    if len(drop) < drop_n:
        return records[-limit:]
    return [r for i, r in enumerate(records) if i not in drop]

def _write_records(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    data = json.dumps(_cap(records), ensure_ascii=False, indent=1).encode()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def _mutate(journal_dir, fn):
    path = _journal_path(journal_dir)
    os.makedirs(journal_dir, exist_ok=True)
    lock_path = path + ".lock"
    with open(lock_path, "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            records = []
            if os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        records = json.load(f)
                except Exception:
                    records = []
            if not isinstance(records, list):
                records = []
            fn(records)
            _write_records(path, records)
            return records
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)

def _latest(records, kind, to, sha):
    for rec in reversed(records):
        if rec.get("kind") == kind and rec.get("to") == to and rec.get("sha256") == sha:
            return rec
    return None

def _public_result(**kw):
    base = {
        "status": "LOCAL_REJECT", "exit_code": 2, "api_accepted": False,
        "recipient_delivered": None, "recipient_delivery_known": False,
        "read_receipt": None, "read_receipt_supported": False,
        "safe_to_retry": False, "kind": None, "format": None, "animated": None,
        "frame_count": None, "conversion": "none", "bytes": None,
        "ciphertext_bytes": None, "sha256": None, "rawfilemd5": None,
        "file_name": None, "to": None, "client_id": None, "server_message_id": None,
        "caption_client_id": None, "caption_server_message_id": None,
        "caption_status": "none", "ret": None, "errcode": None, "errmsg": None,
        "note": "",
    }
    base.update(kw)
    return base

def _note_history(line, history_path):
    try:
        history.append(line, path=history_path)
    except Exception:
        pass

def _history_label(kind, name, animated):
    if kind == "image":
        return "[图片 %s%s]" % (name, " 动图" if animated else "")
    return "[文件 %s]" % name

def _classify_send_exception(exc):
    if isinstance(exc, urllib.error.HTTPError):
        if 400 <= exc.code < 500:
            return "rejected", "sendmessage HTTP %s" % exc.code
        return "uncertain", "sendmessage HTTP %s after the request was written" % exc.code
    if isinstance(exc, (TimeoutError,)):
        return "uncertain", "sendmessage timed out after the request was written"
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, (TimeoutError,)):
            return "uncertain", "sendmessage timed out after the request was written"
        return "uncertain", "sendmessage connection failed after the request was written"
    if isinstance(exc, LocalError):
        return "rejected", str(exc)
    return "uncertain", "sendmessage failed after the request was written (%s)" % type(exc).__name__

def _post_message(transport, body, timeout):
    try:
        raw = transport.api_post("ilink/bot/sendmessage", body, timeout)
    except Exception as e:
        kind, why = _classify_send_exception(e)
        return kind, why, {}
    ok, obj = api_ok(raw if isinstance(raw, str) else json.dumps(raw))
    if ok is None:
        return "uncertain", "sendmessage returned a non-JSON body", {}
    if not ok:
        return "rejected", obj.get("errmsg") or "sendmessage refused", obj
    return "accepted", "", obj

def _upload(transport, plaintext, to, media_type):
    filekey = secrets.token_hex(16)
    key = secrets.token_bytes(16)
    ct = encrypt_aes128_ecb(plaintext, key)
    expect = padded_size(len(plaintext))
    if len(ct) != expect or len(ct) % 16:
        raise LocalError("ciphertext length does not match PKCS#7")
    body = build_upload_body(filekey, media_type, to, len(plaintext),
                             hashlib.md5(plaintext, usedforsecurity=False).hexdigest(),
                             len(ct), key.hex())
    try:
        raw = transport.api_post("ilink/bot/getuploadurl", body, 20)
    except Exception as e:
        raise LocalError("getuploadurl failed before any message was sent (%s)" % type(e).__name__)
    ok, obj = api_ok(raw if isinstance(raw, str) else json.dumps(raw))
    if ok is None or not ok:
        why = (obj or {}).get("errmsg") if isinstance(obj, dict) else ""
        raise LocalError("getuploadurl refused (%s); nothing was sent" % (why or "no upload url"))
    url = build_upload_url(obj.get("upload_full_url"), obj.get("upload_param"), filekey)
    if not upload_url_allowed(url):
        raise LocalError("getuploadurl returned an upload URL outside the documented CDN; nothing was sent")
    last = "cdn upload failed"
    for attempt in range(1, CDN_UPLOAD_ATTEMPTS + 1):
        try:
            resp = transport.cdn_post(url, ct, 60)
        except CDNHTTPError as e:
            if 400 <= e.status < 500:
                raise LocalError("CDN upload rejected HTTP %s; nothing was sent" % e.status)
            last = "CDN HTTP %s" % e.status
            continue
        except LocalError:
            raise
        except Exception as e:
            last = "CDN upload error %s" % type(e).__name__
            continue
        status = int(resp.get("status") or 0)
        param = resp.get("encrypted_param") or ""
        if status == 200 and param:
            return {"filekey": filekey, "aeskey": key, "ciphertext": ct, "download_param": param, "upload_body": body}
        if 400 <= status < 500:
            raise LocalError("CDN upload rejected HTTP %s; nothing was sent" % status)
        last = "CDN status %s missing x-encrypted-param" % status
    raise LocalError("%s after %d attempts; no message was sent" % (last, CDN_UPLOAD_ATTEMPTS))

def send_path(path, kind, to=None, context_token=None, caption=None, confirm_resend=False,
              client_id=None, journal_dir=None, transport=None, history_path=None, timeout=20):
    """Upload and send one image or file. Returns a result dict. Does not queue in outbox."""
    journal_dir = journal_dir or config.DATA_DIR
    transport = transport or IlinkTransport()
    try:
        info = load_media(path, kind)
        client_id = _check_client_id(client_id)
        to, context_token = resolve_recipient(to, context_token)
    except LocalError as e:
        return _public_result(note=str(e), safe_to_retry=False)
    except Exception as e:
        return _public_result(note="cannot prepare send (%s)" % type(e).__name__)

    caption = caption or ""
    cap_hash = hashlib.sha256(caption.encode("utf-8")).hexdigest() if caption else ""
    common = {"kind": kind, "format": info["format"], "animated": info["animated"],
              "frame_count": info["frame_count"], "conversion": "none", "bytes": len(info["data"]),
              "sha256": info["sha256"], "rawfilemd5": info["rawfilemd5"], "file_name": info["file_name"],
              "to": to}

    blocked = {}
    def _look(records):
        prior = _latest(records, kind, to, info["sha256"])
        blocked["prior"] = prior
    _mutate(journal_dir, _look)
    prior = blocked.get("prior")
    if prior and prior.get("stage") in UNRESOLVED and not confirm_resend:
        return _public_result(
            status="BLOCKED", exit_code=6, api_accepted=None, safe_to_retry=False,
            client_id=prior.get("inflight_client_id"), caption_client_id=prior.get("caption_client_id"),
            caption_status=prior.get("caption_status") or "none", note=(
                "a previous send of this file has an ambiguous outcome (client_id %s). "
                "Nothing new was sent. Do not retry unless you accept a possible duplicate: "
                "--confirm-resend --client-id %s" % (prior.get("inflight_client_id"), prior.get("inflight_client_id"))
            ), **{k: common[k] for k in common if k != "to"}, to=to)

    skip_caption = False
    caption_client = None
    media_client = client_id
    if prior and confirm_resend and prior.get("stage") in UNRESOLVED:
        if prior.get("inflight") == "caption":
            caption_client = client_id or prior.get("caption_client_id")
            media_client = None
        elif prior.get("inflight") == "media":
            media_client = client_id or prior.get("media_client_id")
            # The caption sendmessage already happened or was not the ambiguous call.
            # Repeating it on a file-send retry can deliver a second text bubble.
            skip_caption = prior.get("caption_status") in ("accepted", "skipped") or not caption
    elif prior and prior.get("caption_status") == "accepted" and prior.get("media_status") != "accepted" and prior.get("caption_sha256") == cap_hash:
        skip_caption = True

    rec_id = secrets.token_hex(8)
    state = {"id": rec_id, "kind": kind, "to": to, "sha256": info["sha256"], "bytes": len(info["data"]),
             "file_name": info["file_name"], "caption_sha256": cap_hash, "caption_status": "skipped" if skip_caption else "none",
             "caption_client_id": None, "media_client_id": None, "media_status": "none",
             "stage": "prepared", "inflight": None, "inflight_client_id": None,
             "started_at": time.time(), "updated_at": time.time()}

    def _save(stage, **extra):
        def fn(records):
            state["stage"] = stage
            state["updated_at"] = time.time()
            state.update(extra)
            found = False
            for i, rec in enumerate(records):
                if rec.get("id") == rec_id:
                    records[i] = dict(state)
                    found = True
                    break
            if not found:
                records.append(dict(state))
            if prior and prior.get("id") and stage in UNRESOLVED:
                for rec in records:
                    if rec.get("id") == prior.get("id") and rec.get("stage") in UNRESOLVED:
                        rec["stage"] = "retried"
                        rec["updated_at"] = time.time()
        _mutate(journal_dir, fn)

    caption_status = "none"
    caption_server = None
    if caption and not skip_caption:
        caption_client = caption_client or new_client_id()
        _save("sending_caption", inflight="caption", inflight_client_id=caption_client, caption_client_id=caption_client)
        kind_s, why, obj = _post_message(transport, build_send_body(
            to, caption_client, build_text_item(caption), context_token), timeout)
        caption_server = server_message_id(obj)
        if kind_s == "accepted":
            caption_status = "accepted"
            _save("caption_accepted", caption_status="accepted", inflight=None)
            _note_history(history.grok_line(caption), history_path)
        elif kind_s == "rejected":
            _save("rejected", caption_status="rejected", media_status="none")
            return _public_result(status="REJECTED", exit_code=5, api_accepted=False, safe_to_retry=True,
                                  caption_client_id=caption_client, caption_server_message_id=caption_server,
                                  caption_status="rejected", ret=obj.get("ret"), errcode=obj.get("errcode"),
                                  errmsg=obj.get("errmsg"), client_id=caption_client,
                                  note="caption was refused; the file was not uploaded. Safe to retry. " + str(why or ""),
                                  **common)
        else:
            _save("uncertain", caption_status="uncertain")
            return _public_result(status="UNCERTAIN", exit_code=6, api_accepted=None, safe_to_retry=False,
                                  caption_client_id=caption_client, caption_status="uncertain", client_id=caption_client,
                                  note=("caption sendmessage outcome is ambiguous (%s). The file was not uploaded. "
                                        "Do not retry without --confirm-resend --client-id %s. A retry can duplicate the caption "
                                        "if WeChat already accepted it. client_id is a correlation id, not proof of delivery."
                                        % (why, caption_client)), **common)
    elif skip_caption:
        caption_status = "skipped"

    try:
        uploaded = _upload(transport, info["data"], to, 1 if kind == "image" else 3)
    except LocalError as e:
        _save("upload_failed", media_status="none", inflight=None)
        return _public_result(status="REJECTED", exit_code=5, api_accepted=False, safe_to_retry=True,
                              caption_client_id=caption_client, caption_server_message_id=caption_server,
                              caption_status=caption_status or ("accepted" if skip_caption else "none"),
                              note=str(e) + (" Caption was already accepted and will not be sent again for the same caption text." if caption_status in ("accepted", "skipped") and caption else ""),
                              **common)

    media_client = media_client or new_client_id()
    item = (build_image_item(uploaded["download_param"], uploaded["aeskey"], len(uploaded["ciphertext"]))
            if kind == "image" else
            build_file_item(uploaded["download_param"], uploaded["aeskey"], info["file_name"], len(info["data"])))
    _save("sending_media", inflight="media", inflight_client_id=media_client, media_client_id=media_client,
          caption_status=caption_status or state.get("caption_status") or "none", caption_client_id=caption_client)
    kind_s, why, obj = _post_message(transport, build_send_body(to, media_client, item, context_token), timeout)
    sid = server_message_id(obj)
    if kind_s == "accepted":
        _save("accepted", media_status="accepted", inflight=None)
        _note_history(history.grok_line(_history_label(kind, info["file_name"], info["animated"])), history_path)
        return _public_result(
            status="API_ACCEPTED", exit_code=0, api_accepted=True, safe_to_retry=False,
            ciphertext_bytes=len(uploaded["ciphertext"]), client_id=media_client, server_message_id=sid,
            caption_client_id=caption_client, caption_server_message_id=caption_server,
            caption_status=caption_status or ("skipped" if skip_caption else "none"),
            ret=obj.get("ret"), errcode=obj.get("errcode"), errmsg=obj.get("errmsg"),
            note=("sendmessage accepted this request (ret/errcode not set, or zero). "
                  "That is API acceptance only. The iLink sendmessage response has no delivery "
                  "or read receipt, so this does not mean the WeChat client showed the file. "
                  "client_id is our correlation id. server_message_id is present only if the API returned one."),
            **common)
    if kind_s == "rejected":
        _save("rejected", media_status="rejected", inflight=None)
        return _public_result(
            status="REJECTED", exit_code=5, api_accepted=False, safe_to_retry=True,
            ciphertext_bytes=len(uploaded["ciphertext"]), client_id=media_client, server_message_id=sid,
            caption_client_id=caption_client, caption_server_message_id=caption_server,
            caption_status=caption_status or ("skipped" if skip_caption else "none"),
            ret=obj.get("ret"), errcode=obj.get("errcode"), errmsg=obj.get("errmsg"),
            note=("sendmessage explicitly refused the file (%s). It was not accepted. "
                  "A later retry sends the file again. An already accepted caption is not repeated "
                  "when the caption text is unchanged." % (why or "ret/errcode")),
            **common)
    _save("uncertain", media_status="uncertain")
    return _public_result(
        status="UNCERTAIN", exit_code=6, api_accepted=None, safe_to_retry=False,
        ciphertext_bytes=len(uploaded["ciphertext"]), client_id=media_client,
        caption_client_id=caption_client, caption_server_message_id=caption_server,
        caption_status=caption_status or ("skipped" if skip_caption else "none"),
        note=("the file sendmessage was dispatched and the outcome is ambiguous (%s). "
              "Nothing will be retried automatically. Retrying can deliver a second copy. "
              "If you retry, pass --confirm-resend --client-id %s. Reusing client_id is a correlation "
              "hint described by the reference client as a dedupe id; this program does not claim the "
              "server will suppress a duplicate. API acceptance was not confirmed, and delivery was not reported."
              % (why, media_client)),
        **common)

def format_result(result):
    lines = [
        "status: %s" % result.get("status"),
        "api_accepted: %s" % {True: "yes", False: "no", None: "unknown"}[result.get("api_accepted") if result.get("api_accepted") in (True, False, None) else None],
        "recipient_delivered: unknown",
        "read_receipt: not_provided_by_ilink_sendmessage",
        "safe_to_retry: %s" % ("yes" if result.get("safe_to_retry") else "no"),
        "client_id: %s" % (result.get("client_id") or ""),
        "server_message_id: %s" % (result.get("server_message_id") or ""),
        "caption_client_id: %s" % (result.get("caption_client_id") or ""),
        "caption_server_message_id: %s" % (result.get("caption_server_message_id") or ""),
        "caption_status: %s" % result.get("caption_status"),
        "kind: %s" % (result.get("kind") or ""),
        "format: %s" % (result.get("format") or ""),
        "bytes: %s" % (result.get("bytes") if result.get("bytes") is not None else ""),
        "animated: %s" % result.get("animated"),
        "frame_count: %s" % result.get("frame_count"),
        "conversion: %s" % result.get("conversion"),
        "file_name: %s" % (result.get("file_name") or ""),
        "note: %s" % (result.get("note") or ""),
        "MEDIA_RESULT " + json.dumps(result, ensure_ascii=False, sort_keys=True),
    ]
    return "\n".join(lines)
