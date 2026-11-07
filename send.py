#!/usr/bin/env python3
"""Send to the bound WeChat user. This is what the agent calls to reply.

Text (unchanged):
  python3 send.py "text" [--to USER_ID] [--no-context] [--app] [--reply-to-ms MS]
  --reply-to-ms: the trigger_ms of the WeChat batch this reply answers. If the user has sent a newer
    message since, nothing is sent and the exit code is 4 (SUPERSEDED): the newer run will answer.
  --app: prefix APP_PREFIX (default "[grok bot] ") for pushes not triggered by the WeChat webhook
    (reminders, routine output), so the user can tell them apart from replies.
  If WeChat refuses (the ~24h window since the user's last message has closed), the text is queued in
  outbox.json (exit code 3) and forward.py sends it automatically the next time the user writes.
  Exit codes: 0 sent, 3 queued, 4 superseded.

Image or file (does not use the text outbox, and does not change the text command above):
  python3 send.py --image PATH [--caption TEXT] [--to USER_ID] [--no-context] [--app] [--reply-to-ms MS]
  python3 send.py --file PATH [--caption TEXT] [--to USER_ID] [--no-context] [--app] [--reply-to-ms MS]
  --image accepts JPG, PNG, GIF, and WEBP and sends them as an image bubble, original bytes, no transcode.
  --file sends PDF, DOC, DOCX, ZIP, or any other non-secret file as a file attachment.
  Exit codes: 0 API accepted (not delivery), 2 not sent (bad input), 4 superseded, 5 explicitly refused,
  6 ambiguous network outcome or blocked so it is not sent twice. There is no exit 3 for media.
"""
import argparse, sys
import outbox
from config import APP_PREFIX, OWNER_NAME

def main(argv=None):
    p = argparse.ArgumentParser(description="Send a WeChat text, or an image/file attachment.")
    p.add_argument("text", nargs="?")
    p.add_argument("--to")
    p.add_argument("--no-context", action="store_true")
    p.add_argument("--app", action="store_true", help="prefix APP_PREFIX for sends not triggered by the WeChat webhook")
    p.add_argument("--reply-to-ms", type=int)
    p.add_argument("--image", help="send this JPG/PNG/GIF/WEBP as an image")
    p.add_argument("--file", help="send this PDF/DOC/ZIP or other file as an attachment")
    p.add_argument("--caption", help="optional text sent before --image/--file")
    p.add_argument("--confirm-resend", action="store_true", help="resend after an ambiguous media outcome")
    p.add_argument("--client-id", help="reuse the correlation id from an ambiguous media send")
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return e.code
    if a.reply_to_ms is not None:
        last = outbox.last_inbound_s()
        if last and last * 1000 > a.reply_to_ms + 500:
            print("SUPERSEDED: %s sent a newer message; not sending. Stop this run without filing anything." % OWNER_NAME)
            return 4
    media = bool(a.image or a.file or a.caption or a.confirm_resend or a.client_id)
    if media:
        if a.text:
            print('usage: a text send has no --image/--file; put attachment text in --caption', file=sys.stderr)
            return 2
        if bool(a.image) == bool(a.file):
            print("usage: pass exactly one of --image PATH or --file PATH", file=sys.stderr)
            return 2
        import media_send
        caption = a.caption or ""
        if a.app and caption:
            caption = APP_PREFIX + caption
        result = media_send.send_path(
            a.image or a.file, "image" if a.image else "file", to=a.to,
            context_token="" if a.no_context else None, caption=caption,
            confirm_resend=a.confirm_resend, client_id=a.client_id)
        print(media_send.format_result(result))
        return result["exit_code"]
    if not a.text:
        print('usage: python3 send.py "text" [--to USER_ID] [--no-context] [--app] [--reply-to-ms MS]', file=sys.stderr)
        return 2
    text = (APP_PREFIX + a.text) if a.app else a.text
    sent, resp = outbox.send_or_queue(text, to=a.to, context_token="" if a.no_context else None)
    print("sent:" if sent else "QUEUED (will auto-send when the user next writes):", resp)
    return 0 if sent else 3

if __name__ == "__main__":
    sys.exit(main())
