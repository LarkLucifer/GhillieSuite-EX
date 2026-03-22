"""
HTML response compaction for LLM prompts.

Goals:
- Strip scripts, styles, SVGs, HTML comments, and base64 images.
- Preserve meaningful structure: forms, inputs/hidden fields, and visible text/errors.
- Keep output compact and fast to generate.
"""

from __future__ import annotations

import re
from typing import Iterable

_DATA_IMAGE_RE = re.compile(r"data:image/[^;]+;base64,[a-z0-9+/=]+", re.IGNORECASE)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_STRIP_TAGS_RE = re.compile(r"<[^>]+>")
_SCRIPT_STYLE_SVG_RE = re.compile(
    r"<(script|style|svg)\b[\s\S]*?</\1>",
    re.IGNORECASE,
)


def _looks_like_html(text: str) -> bool:
    if not text:
        return False
    sample = text[:2000].lower()
    if "<" not in sample or ">" not in sample:
        return False
    return any(token in sample for token in (
        "<html", "<!doctype", "<head", "<body", "<form", "<input", "<div", "<span", "<title",
    ))


def _strip_base64_images(text: str) -> str:
    if not text:
        return ""
    return _DATA_IMAGE_RE.sub("data:image;base64,[stripped]", text)


def _collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _trim(text: str, max_chars: int) -> str:
    if max_chars and len(text) > max_chars:
        return text[:max_chars]
    return text


def _dedupe_preserve(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = (item or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _fallback_compact(text: str, max_chars: int) -> str:
    # Minimal regex-based sanitizer when BeautifulSoup isn't available.
    cleaned = _strip_base64_images(text)
    cleaned = _HTML_COMMENT_RE.sub(" ", cleaned)
    cleaned = _SCRIPT_STYLE_SVG_RE.sub(" ", cleaned)
    cleaned = _STRIP_TAGS_RE.sub(" ", cleaned)
    cleaned = _collapse_ws(cleaned)
    return _trim(cleaned, max_chars)


def preprocess_http_body_for_llm(body: str, content_type: str = "", max_chars: int = 1200) -> str:
    """
    Compact HTTP response bodies before sending to the LLM.
    - HTML: remove scripts/styles/svg/comments/base64 images; summarize forms/inputs/text/errors.
    - Non-HTML: strip base64 images and trim.
    """
    if not body:
        return ""

    body = _strip_base64_images(body)
    content_type = (content_type or "").lower()
    is_html = "html" in content_type or _looks_like_html(body)
    if not is_html:
        return _trim(body.strip(), max_chars)

    try:
        from bs4 import BeautifulSoup, Comment  # type: ignore
    except Exception:
        return _fallback_compact(body, max_chars)

    soup = BeautifulSoup(body, "html.parser")

    # Strip HTML comments
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        comment.extract()

    # Remove noisy tags
    for tag in soup.find_all(["script", "style", "svg"]):
        tag.decompose()

    # Remove base64 images and any inline data:image attrs
    for tag in soup.find_all(True):
        # Drop <img src="data:image/..."> entirely
        src = tag.attrs.get("src")
        if isinstance(src, str) and _DATA_IMAGE_RE.search(src):
            if tag.name == "img":
                tag.decompose()
                continue
            tag.attrs.pop("src", None)

        # Remove any other attributes with base64 image data
        for attr, val in list(tag.attrs.items()):
            if isinstance(val, str) and _DATA_IMAGE_RE.search(val):
                tag.attrs.pop(attr, None)
            elif isinstance(val, list):
                cleaned = [v for v in val if not (isinstance(v, str) and _DATA_IMAGE_RE.search(v))]
                if cleaned:
                    tag.attrs[attr] = cleaned
                else:
                    tag.attrs.pop(attr, None)

    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()

    # Summarize forms + inputs
    form_lines: list[str] = []
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "GET").upper()
        line = f"Form: method={method}"
        if action:
            line += f" action={action}"
        form_lines.append(line)

        for field in form.find_all(["input", "select", "textarea"]):
            ftype = (field.get("type") or field.name or "").lower()
            name = (field.get("name") or "").strip()
            fid = (field.get("id") or "").strip()
            placeholder = (field.get("placeholder") or "").strip()
            value = ""
            if ftype == "hidden" or field.get("value") is not None or field.name in ("select", "textarea"):
                if field.name == "textarea":
                    value = field.get_text(" ", strip=True)
                elif field.name == "select":
                    opt = field.find("option", selected=True) or field.find("option")
                    if opt:
                        value = opt.get("value") or opt.get_text(" ", strip=True)
                else:
                    value = str(field.get("value") or "")
                value = value.strip()

            bits: list[str] = []
            if ftype:
                bits.append(f"type={ftype}")
            if name:
                bits.append(f"name={name}")
            if fid:
                bits.append(f"id={fid}")
            if placeholder:
                bits.append(f"placeholder={placeholder}")
            if value:
                bits.append(f"value={_trim(value, 120)}")
            if bits:
                form_lines.append("Input: " + " ".join(bits))

        if len(form_lines) > 80:
            break

    # Inputs outside of forms
    orphan_lines: list[str] = []
    for field in soup.find_all(["input", "select", "textarea"]):
        if field.find_parent("form") is not None:
            continue
        ftype = (field.get("type") or field.name or "").lower()
        name = (field.get("name") or "").strip()
        fid = (field.get("id") or "").strip()
        placeholder = (field.get("placeholder") or "").strip()
        value = ""
        if ftype == "hidden" or field.get("value") is not None or field.name in ("select", "textarea"):
            if field.name == "textarea":
                value = field.get_text(" ", strip=True)
            elif field.name == "select":
                opt = field.find("option", selected=True) or field.find("option")
                if opt:
                    value = opt.get("value") or opt.get_text(" ", strip=True)
            else:
                value = str(field.get("value") or "")
            value = value.strip()

        bits: list[str] = []
        if ftype:
            bits.append(f"type={ftype}")
        if name:
            bits.append(f"name={name}")
        if fid:
            bits.append(f"id={fid}")
        if placeholder:
            bits.append(f"placeholder={placeholder}")
        if value:
            bits.append(f"value={_trim(value, 120)}")
        if bits:
            orphan_lines.append("Input: " + " ".join(bits))
        if len(orphan_lines) > 20:
            break

    # Extract error/alert text
    error_lines: list[str] = []
    for elem in soup.find_all(True):
        role = (elem.get("role") or "").lower()
        cls_val = elem.get("class")
        if isinstance(cls_val, list):
            cls = " ".join(cls_val).lower()
        else:
            cls = str(cls_val or "").lower()
        ident = (elem.get("id") or "").lower()
        if role in ("alert", "status") or any(
            k in cls or k in ident for k in ("error", "invalid", "warning", "alert", "denied", "forbidden")
        ):
            txt = elem.get_text(" ", strip=True)
            if txt:
                error_lines.append(txt)
        if len(error_lines) >= 8:
            break
    error_lines = _dedupe_preserve(error_lines)

    # Visible text
    text_chunks: list[str] = []
    for s in soup.stripped_strings:
        if s:
            text_chunks.append(s)
        if len(text_chunks) >= 200:
            break
    text_chunks = _dedupe_preserve(text_chunks)

    parts: list[str] = []
    if title:
        parts.append(f"Title: {title}")
    if form_lines:
        parts.append("Forms:\n" + "\n".join(form_lines))
    if orphan_lines:
        parts.append("Orphan Inputs:\n" + "\n".join(orphan_lines))
    if error_lines:
        parts.append("Errors: " + " | ".join(error_lines))
    if text_chunks:
        parts.append("Visible Text: " + " ".join(text_chunks))

    summary = "\n".join(parts).strip()
    summary = summary or _collapse_ws(soup.get_text(" ", strip=True))
    return _trim(summary, max_chars)
