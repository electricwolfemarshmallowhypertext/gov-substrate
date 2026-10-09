"""Host-registered tool executors. Connection settings never come from the agent."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import smtplib
from email.message import EmailMessage
from typing import Any, Callable, Protocol


class ToolAdapter(Protocol):
    external_transfer: bool
    identity: dict[str, Any]

    def validate(self, arguments: dict[str, Any]) -> None: ...
    def execute(self, arguments: dict[str, Any]) -> dict[str, Any]: ...


class SMTPSendEmailAdapter:
    """Deliver real mail to an operator-configured loopback SMTP service only."""

    external_transfer = True

    def __init__(self, host: str, port: int, sender: str,
                 attachment_resolver: Callable[[dict], tuple[str, bytes]] | None = None):
        if not ipaddress.ip_address(host).is_loopback or not 1 <= port <= 65535:
            raise ValueError("SMTP sink must be a literal loopback address")
        self.host, self.port, self.sender = host, port, sender
        self.attachment_resolver = attachment_resolver
        self.identity = {"executor": "loopback-smtp-v1", "host": host, "port": port,
                         "sender": sender, "attachments": attachment_resolver is not None}

    def validate(self, arguments):
        if (type(arguments) is not dict or
                set(arguments) - {"recipients", "subject", "body", "attachments", "cc", "bcc"} or
                not {"recipients", "subject", "body"} <= set(arguments)):
            raise ValueError("invalid send_email arguments")
        for field in ("recipients", "cc", "bcc"):
            values = arguments.get(field)
            if values is None and field != "recipients":
                values = []
            if (type(values) is not list or len(values) > 50 or
                    any(type(value) is not str or "@" not in value or
                        any(c in value for c in "\r\n") for value in values)):
                raise ValueError("invalid email recipients")
        if not arguments["recipients"]:
            raise ValueError("email requires recipients")
        if (type(arguments["subject"]) is not str or type(arguments["body"]) is not str or
                any(c in arguments["subject"] for c in "\r\n") or
                len(json.dumps(arguments).encode()) > 131072):
            raise ValueError("invalid email content")
        attachments = arguments.get("attachments")
        if attachments is None:
            attachments = []
        if type(attachments) is not list or any(type(item) is not dict for item in attachments):
            raise ValueError("invalid attachments")
        if attachments and self.attachment_resolver is None:
            raise ValueError("attachment resolver not configured")

    def execute(self, arguments):
        self.validate(arguments)
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = ", ".join(arguments["recipients"])
        message["Subject"] = arguments["subject"]
        if arguments.get("cc"):
            message["Cc"] = ", ".join(arguments["cc"])
        message.set_content(arguments["body"])
        for item in arguments.get("attachments") or []:
            filename, content = self.attachment_resolver(item)
            message.add_attachment(content, maintype="application", subtype="octet-stream",
                                   filename=filename)
        recipients = (arguments["recipients"] + (arguments.get("cc") or []) +
                      (arguments.get("bcc") or []))
        with smtplib.SMTP(self.host, self.port, timeout=5) as connection:
            refused = connection.send_message(message, from_addr=self.sender,
                                              to_addrs=recipients)
        if refused:
            raise ValueError("SMTP refused recipients")
        return {"accepted_recipients": len(recipients),
                "message_sha256": hashlib.sha256(message.as_bytes()).hexdigest()}
