"""Data models for webhook relay pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AttachmentType(str, Enum):
    """Types of file attachments that can arrive via Telegram."""

    IMAGE = "image"
    DOCUMENT = "document"
    AUDIO = "audio"
    VOICE = "voice"
    VIDEO = "video"
    STICKER = "sticker"


@dataclass
class Attachment:
    """A downloaded file attachment from a Telegram message."""

    type: AttachmentType
    file_id: str
    mime_type: str
    file_name: str
    file_size: int
    data: bytes


@dataclass
class WebhookMessage:
    """Normalized inbound webhook message for pipeline processing."""

    source: str  # "telegram" or "whatsapp"
    text: str
    sender_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    attachments: list[Attachment] = field(default_factory=list)


@dataclass
class WebhookResponse:
    """Pipeline response to return to the originating platform."""

    text: str
    status_code: int
