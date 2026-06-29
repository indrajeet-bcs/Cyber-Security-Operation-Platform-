import base64
import codecs
import csv
import gzip
import hashlib
import io
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from app.utils.logger import logger

# ─── Syslog Regex Definitions ─────────────────────────────────────────────────

# RFC 3164: <PRI>MMM DD HH:MM:SS HOST TAG[PID]: MESSAGE
# Allow multiple spaces in timestamp day (e.g. Oct  1)
_SYSLOG_3164_RE = re.compile(
    r'^<(?P<pri>\d+)>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>[^\s]+)\s+(?P<tag>[a-zA-Z0-9_\-\/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOST APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_SYSLOG_5424_RE = re.compile(
    r'^<(?P<pri>\d+)>1\s+(?P<timestamp>[^\s]+)\s+(?P<host>[^\s]+)\s+(?P<app_name>[^\s]+)\s+'
    r'(?P<procid>[^\s]+)\s+(?P<msgid>[^\s]+)\s+(?P<structured_data>\[.*\]|-)\s*(?P<message>.*)$'
)

# NCSA Combined Log Format (Web logs)
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "ref" "ua"
_WEB_LOG_RE = re.compile(
    r'^(?P<ip>[^\s]+)\s+(?P<ident>[^\s]+)\s+(?P<authuser>[^\s]+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<request>[^\s"]*)\s*(?P<protocol>[^"]*)?"'
    r'\s+(?P<status>\d+)\s+(?P<bytes>[^\s]+)'
    r'(?:\s+"(?P<referrer>[^\"]*)"\s+"(?P<user_agent>[^\"]*)")?$'
)

# ─── CEF / LEEF Regex Definitions ─────────────────────────────────────────────

# CEF: CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|DeviceEventClassId|Name|Severity|[Extension]
_CEF_RE = re.compile(
    r'^CEF:(?P<cef_version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|'
    r'(?P<dev_version>[^|]*)\|(?P<event_id>[^|]*)\|(?P<name>[^|]*)\|'
    r'(?P<severity>[^|]*)\|?(?P<extensions>.*)$',
    re.IGNORECASE,
)

# LEEF: LEEF:Version|Vendor|Product|Version|EventID|[Attributes]
_LEEF_RE = re.compile(
    r'^LEEF:(?P<leef_version>[^|]*)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|'
    r'(?P<dev_version>[^|]*)\|(?P<event_id>[^|]*)\|?(?P<attributes>.*)$',
    re.IGNORECASE,
)

# Key=Value pair extraction: key=value  OR  key="quoted value"  OR  key='single quoted' (supports unquoted multi-word values)
_KV_PAIR_RE = re.compile(
    r'([\w][\w.\-]*)\s*=\s*(?:"([^"\\]*(?:\\.[^"\\]*)*)"|\'([^\'\\]*(?:\\.[^\'\\]*)*)\'|([^\s]+(?:\s+(?![\w.\-]+\s*=)[^\s]+)*))'
)

# Windows Event XML namespace URI
_WIN_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


class ParsingService:
    """
    Advanced log parsing and decoding service for the SOC platform.

    Pipeline (in order):
      1. Extract message text from raw_input (Pydantic model / dict / str)
      2. Decoding loop — up to 5 recursive passes:
           URL → Escaped → Unicode-escape → Gzip → Base64 → Hex
      3. Format detection and structured parsing:
           Windows Event XML → CEF → LEEF → JSON/Docker → Syslog → Web → Key=Value → CSV
      4. Merge parsed fields back into original payload
      5. Generate SHA-256 event_fingerprint

    Returns a dict with:
      parsing_status   : "success" | "failed"
      detected_format  : str
      decoding_applied : bool          (backward-compatible)
      decoding_chain   : list[str]     (ordered decodings applied)
      parsing_confidence: float        (0.0–1.0)
      event_fingerprint: str           (SHA-256 hex)
      payload          : dict
    """

    # Windows Event Level → SOC severity
    _WIN_LEVEL_SEVERITY: dict[int, str] = {
        0: "low",       # Information (no explicit level — common in Security/System)
        1: "critical",  # Critical
        2: "high",      # Error
        3: "medium",    # Warning
        4: "low",       # Information
        5: "low",       # Verbose
    }

    # CEF text severity label → SOC severity
    _CEF_SEVERITY_MAP: dict[str, str] = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "very-high": "critical",
        "unknown": "low",
    }

    # ─── Public Entry Point ──────────────────────────────────────────────────

    def parse_and_decode_log(self, raw_input: Any) -> dict:
        """
        Main entry point. Accepts a RawLogIngest model, dict, or raw string.
        Returns the full parsing result dict.
        """
        logger.info("[INFO] Parsing started")

        # 1. Extract text content and preserve original data dict
        text_content = ""
        original_data: dict = {}
        is_model = hasattr(raw_input, "model_dump")

        if is_model:
            original_data = raw_input.model_dump()
            text_content = original_data.get("message") or ""
        elif isinstance(raw_input, dict):
            original_data = raw_input
            text_content = (
                original_data.get("message")
                or original_data.get("msg")
                or original_data.get("log")
                or ""
            )
        elif isinstance(raw_input, str):
            text_content = raw_input
        else:
            text_content = str(raw_input)

        decodings_applied: list[str] = []
        decoded_text = text_content
        parsing_status = "success"
        detected_format = "text"
        parsing_confidence = 0.3

        try:
            # 2. Run Decoding Loop (up to 5 recursive passes)
            decoded_text, decodings_applied = self._run_decoding_loop(text_content)

            # 3. Detect and parse structured format
            parsed_payload, detected_format, parsing_confidence = self._parse_structured_format(decoded_text)

            # 4. Merge parsed fields back into original payload
            merged_payload: dict = {}
            if original_data:
                merged_payload.update(original_data)

            # Replace message with the clean decoded version
            merged_payload["message"] = decoded_text

            if parsed_payload:
                # Override standard SOC fields with parsed values
                for key in ["source", "host", "event_type", "severity", "timestamp", "source_ip", "user"]:
                    if key in parsed_payload and parsed_payload[key] is not None:
                        merged_payload[key] = parsed_payload[key]

                # Merge metadata — preserve existing, overlay parsed
                existing_meta = merged_payload.get("metadata") or {}
                if not isinstance(existing_meta, dict):
                    existing_meta = {}

                parsed_meta = parsed_payload.get("metadata") or {}
                # Promote non-standard parsed keys into metadata
                for k, v in parsed_payload.items():
                    if k not in [
                        "source", "host", "event_type", "severity", "timestamp",
                        "source_ip", "user", "metadata", "message",
                    ]:
                        parsed_meta[k] = v

                existing_meta.update(parsed_meta)
                merged_payload["metadata"] = existing_meta

            # 5. Generate event fingerprint from final payload
            event_fingerprint = self._generate_fingerprint(merged_payload)

            logger.info(
                f"[INFO] Parsing completed — format={detected_format} "
                f"confidence={parsing_confidence:.2f} "
                f"decodings={decodings_applied}"
            )

            return {
                "parsing_status": parsing_status,
                "detected_format": detected_format,
                "decoding_applied": len(decodings_applied) > 0,   # backward-compatible bool
                "decoding_chain": decodings_applied,               # ordered list
                "parsing_confidence": parsing_confidence,
                "event_fingerprint": event_fingerprint,
                "payload": merged_payload,
            }

        except Exception as exc:
            logger.warning(f"[WARNING] Parsing failed: {exc}")
            fallback_payload = original_data if original_data else {"message": text_content}
            return {
                "parsing_status": "failed",
                "detected_format": "unknown",
                "decoding_applied": len(decodings_applied) > 0,
                "decoding_chain": decodings_applied,
                "parsing_confidence": 0.0,
                "event_fingerprint": self._generate_fingerprint(fallback_payload),
                "payload": fallback_payload,
            }

    # ─── Event Fingerprint ───────────────────────────────────────────────────

    def _generate_fingerprint(self, payload: dict) -> str:
        """
        Generates a SHA-256 fingerprint from 4 key log fields:
            source | event_type | message[:512] | timestamp

        Used for:
          - Cross-source event correlation
          - Advanced duplicate detection (beyond record_number)
          - SOC alert linking and incident tracing
        """
        source = str(payload.get("source") or "")
        event_type = str(payload.get("event_type") or "")
        message = str(payload.get("message") or "")[:512]
        timestamp = str(payload.get("timestamp") or "")
        raw = f"{source}|{event_type}|{message}|{timestamp}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # ─── Decoding Loop ───────────────────────────────────────────────────────

    def _run_decoding_loop(self, text: str) -> tuple[str, list[str]]:
        """
        Attempts up to 5 recursive decoding passes in priority order:
          URL → Escaped → Unicode-escape → Gzip → Base64 → Hex

        Gzip is tried BEFORE Base64/Hex because gzip detector internally
        handles base64-wrapped and hex-wrapped gzip in one step, allowing
        it to short-circuit the individual decoders when compression is found.
        """
        decodings: list[str] = []
        current = text

        for _ in range(5):
            # 1. URL decoding (%xx sequences)
            url_decoded = self._try_decode_url(current)
            if url_decoded:
                current = url_decoded
                decodings.append("url")
                logger.info("[INFO] URL encoding detected")
                continue

            # 2. Escaped character sequences (\n, \t, \\, etc.)
            escaped_decoded = self._try_decode_escaped(current)
            if escaped_decoded:
                current = escaped_decoded
                decodings.append("escaped")
                continue

            # 3. Unicode escape sequences (\uXXXX, \UXXXXXXXX)
            unicode_decoded = self._try_decode_unicode_escape(current)
            if unicode_decoded:
                current = unicode_decoded
                decodings.append("unicode_escape")
                logger.info("[INFO] Unicode escape sequences detected")
                continue

            # 4. Gzip decompression (handles base64-wrapped and hex-wrapped gzip)
            gzip_decoded = self._try_decode_gzip(current)
            if gzip_decoded:
                current = gzip_decoded
                decodings.append("gzip")
                continue

            # 5. Base64 decoding
            b64_decoded = self._try_decode_base64(current)
            if b64_decoded:
                current = b64_decoded
                decodings.append("base64")
                logger.info("[INFO] Base64 detected")
                continue

            # 6. Hex decoding
            hex_decoded = self._try_decode_hex(current)
            if hex_decoded:
                current = hex_decoded
                decodings.append("hex")
                logger.info("[INFO] Hex detected")
                continue

            break

        return current, decodings

    # ─── Individual Decoders ─────────────────────────────────────────────────

    def _try_decode_url(self, text: str) -> str | None:
        if "%" not in text:
            return None
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                return decoded
        except Exception:
            pass
        return None

    def _try_decode_escaped(self, text: str) -> str | None:
        if "\\" not in text:
            return None
        try:
            decoded_bytes, _ = codecs.escape_decode(bytes(text, "utf-8"))
            decoded = decoded_bytes.decode("utf-8")
            if decoded != text:
                return decoded
        except Exception:
            pass
        return None

    def _try_decode_unicode_escape(self, text: str) -> str | None:
        """
        Decodes \\uXXXX (4-digit) and \\UXXXXXXXX (8-digit) Unicode escape sequences.
        Common in Windows Event XML exports and JSON-stringified payloads.
        """
        if "\\u" not in text and "\\U" not in text:
            return None
        try:
            # Decode \uXXXX sequences
            decoded = re.sub(
                r"\\u([0-9a-fA-F]{4})",
                lambda m: chr(int(m.group(1), 16)),
                text,
            )
            # Decode \UXXXXXXXX sequences (8-digit)
            decoded = re.sub(
                r"\\U([0-9a-fA-F]{8})",
                lambda m: chr(int(m.group(1), 16)),
                decoded,
            )
            if decoded != text:
                return decoded
        except Exception:
            pass
        return None

    def _try_decode_gzip(self, text: str) -> str | None:
        """
        Detects and decompresses gzip payloads sent by cloud agents or log shippers.

        Two wrapping strategies are handled:
          - Base64(gzip(plaintext))  — most common in cloud log pipelines
          - Hex(gzip(plaintext))     — less common, used by some network devices

        The gzip magic bytes (0x1f 0x8b) are checked AFTER unwrapping to
        confirm compression before attempting decompression.
        """
        stripped = text.strip()
        if not stripped or len(stripped) < 8:
            return None

        # Strategy 1: base64-wrapped gzip
        if re.match(r"^[A-Za-z0-9+/=\s]+$", stripped):
            try:
                padded = stripped + "=" * (4 - len(stripped) % 4)
                raw_bytes = base64.b64decode(padded)
                if len(raw_bytes) >= 2 and raw_bytes[:2] == b"\x1f\x8b":
                    decompressed = gzip.decompress(raw_bytes)
                    decoded_str = decompressed.decode("utf-8", errors="replace")
                    if all(c.isprintable() or c in "\r\n\t" for c in decoded_str[:200]):
                        logger.info("[INFO] Gzip (base64-wrapped) detected")
                        return decoded_str
            except Exception:
                pass

        # Strategy 2: hex-wrapped gzip
        hex_stripped = "".join(stripped.split())
        if re.match(r"^[0-9a-fA-F]+$", hex_stripped) and len(hex_stripped) % 2 == 0:
            try:
                raw_bytes = bytes.fromhex(hex_stripped)
                if len(raw_bytes) >= 2 and raw_bytes[:2] == b"\x1f\x8b":
                    decompressed = gzip.decompress(raw_bytes)
                    decoded_str = decompressed.decode("utf-8", errors="replace")
                    if all(c.isprintable() or c in "\r\n\t" for c in decoded_str[:200]):
                        logger.info("[INFO] Gzip (hex-wrapped) detected")
                        return decoded_str
            except Exception:
                pass

        return None

    def _try_decode_base64(self, text: str) -> str | None:
        stripped = text.strip()
        if not stripped or len(stripped) < 4:
            return None

        # Must look like valid base64 (A–Z, a–z, 0–9, +, /, =)
        if not re.match(r"^[A-Za-z0-9+/=\s]+$", stripped):
            return None

        missing_padding = len(stripped) % 4
        if missing_padding:
            stripped += "=" * (4 - missing_padding)

        try:
            decoded_bytes = base64.b64decode(stripped)
            decoded_str = decoded_bytes.decode("utf-8")
            # Guard against binary false-positives
            if all(c.isprintable() or c in "\r\n\t" for c in decoded_str):
                return decoded_str
        except Exception:
            pass
        return None

    def _try_decode_hex(self, text: str) -> str | None:
        stripped = "".join(text.strip().split())
        if not stripped or len(stripped) < 4:
            return None

        if not re.match(r"^[0-9a-fA-F]+$", stripped) or len(stripped) % 2 != 0:
            return None

        try:
            decoded_bytes = bytes.fromhex(stripped)
            decoded_str = decoded_bytes.decode("utf-8")
            if all(c.isprintable() or c in "\r\n\t" for c in decoded_str):
                return decoded_str
        except Exception:
            pass
        return None

    # ─── Format Detection & Dispatch ─────────────────────────────────────────

    def _parse_structured_format(self, text: str) -> tuple[dict | None, str, float]:
        """
        Identifies and parses a structured log format.

        Detection order (most specific → least specific):
          Windows Event XML → CEF → LEEF → JSON/Docker → Syslog → Web → Key=Value → CSV

        Returns: (parsed_payload_or_None, format_name, confidence_score)
        Confidence: 1.0 = perfect structured match, 0.3 = plain text fallback.
        """
        text_stripped = text.strip()
        if not text_stripped:
            return None, "text", 0.3

        # 1. Windows Event XML — checked first due to highly specific XML signature
        if "<Event" in text_stripped:
            xml_data = self._parse_windows_event_xml(text_stripped)
            if xml_data:
                return xml_data, "windows_xml", 0.95

        # 2. CEF (Common Event Format — ArcSight, enterprise SIEMs)
        if text_stripped.upper().startswith("CEF:"):
            cef_data = self._parse_cef(text_stripped)
            if cef_data:
                return cef_data, "cef", 1.0

        # 3. LEEF (Log Event Extended Format — IBM QRadar)
        if text_stripped.upper().startswith("LEEF:"):
            leef_data = self._parse_leef(text_stripped)
            if leef_data:
                return leef_data, "leef", 1.0

        # 4. JSON & Nested JSON (including Docker log JSON)
        if (text_stripped.startswith("{") and text_stripped.endswith("}")) or (
            text_stripped.startswith("[") and text_stripped.endswith("]")
        ):
            try:
                data = json.loads(text_stripped)
                if isinstance(data, dict):
                    # Docker log JSON detection: has "log", "stream", "time" keys
                    if "log" in data and "stream" in data and "time" in data:
                        return {
                            "source": f"docker-{data['stream']}",
                            "event_type": "docker_log",
                            "message": data["log"].strip(),
                            "timestamp": data["time"],
                            "metadata": data,
                        }, "json", 0.95
                    return data, "json", 0.9
            except Exception:
                pass

        # 5. Syslog RFC 5424 and RFC 3164
        syslog_data = self._parse_syslog(text_stripped)
        if syslog_data:
            return syslog_data, "syslog", 0.95

        # 6. NCSA Combined Web Log Format (Apache / Nginx)
        web_data = self._parse_web(text_stripped)
        if web_data:
            return web_data, "web", 0.95

        # 7. Key=Value pairs (Cisco, Palo Alto, firewall logs)
        kv_data = self._parse_key_value(text_stripped)
        if kv_data:
            return kv_data, "key_value", 0.7

        # 8. CSV logs (EDR, antivirus tools) — strictest guards to avoid false-positives
        csv_data = self._parse_csv(text_stripped)
        if csv_data:
            return csv_data, "csv", 0.6

        return None, "text", 0.3

    # ─── Format Parsers ──────────────────────────────────────────────────────

    def _parse_windows_event_xml(self, text: str) -> dict | None:
        """
        Parses Windows Event Log XML (Microsoft schema).

        Extracts:
          - EventID, Provider/Name, Level, Channel, Computer (from <System>)
          - TimeCreated SystemTime attribute
          - Named <Data> elements from <EventData>

        Level → severity mapping: 1=critical, 2=high, 3=medium, 0/4/5=low
        """
        try:
            root = ET.fromstring(text.strip())
            ns = {"w": _WIN_EVENT_NS}

            def _find(path: str):
                result = root.find(path, ns)
                if result is None:
                    result = root.find(path.replace("w:", ""))
                return result

            def _findall(path: str):
                results = root.findall(path, ns)
                if not results:
                    results = root.findall(path.replace("w:", ""))
                return results

            if _find("w:System") is None:
                return None

            # EventID
            event_id_el = _find("w:System/w:EventID")
            event_id = event_id_el.text.strip() if event_id_el is not None else "unknown"

            # Provider Name
            provider_el = _find("w:System/w:Provider")
            provider = provider_el.get("Name", "unknown") if provider_el is not None else "unknown"

            # Level → severity
            level_el = _find("w:System/w:Level")
            try:
                level = int(level_el.text.strip()) if level_el is not None else 4
            except (ValueError, AttributeError):
                level = 4
            severity = self._WIN_LEVEL_SEVERITY.get(level, "low")

            # TimeCreated SystemTime
            time_el = _find("w:System/w:TimeCreated")
            timestamp = time_el.get("SystemTime") if time_el is not None else None

            # Channel
            channel_el = _find("w:System/w:Channel")
            channel = channel_el.text.strip() if channel_el is not None else "unknown"

            # Computer hostname
            computer_el = _find("w:System/w:Computer")
            computer = computer_el.text.strip() if computer_el is not None else None

            # EventData — named <Data Name="..."> elements
            event_data: dict = {}
            for data_el in _findall("w:EventData/w:Data"):
                name = data_el.get("Name") or f"field_{len(event_data)}"
                event_data[name] = data_el.text or ""

            # Build human-readable message
            if event_data:
                pairs_preview = " | ".join(f"{k}={v}" for k, v in list(event_data.items())[:5])
                message = f"Windows Event {event_id} [{provider}]: {pairs_preview}"
            else:
                message = f"Windows Event {event_id} from {provider} on channel {channel}"

            result: dict = {
                "source": provider,
                "host": computer,
                "event_type": f"windows_event_{event_id}",
                "message": message,
                "severity": severity,
                "metadata": {
                    "event_id": event_id,
                    "provider": provider,
                    "channel": channel,
                    "level": level,
                    "event_data": event_data,
                    "format": "windows_xml",
                },
            }
            if timestamp:
                result["timestamp"] = timestamp

            return result

        except ET.ParseError:
            return None
        except Exception as exc:
            logger.warning(f"[WARNING] Windows Event XML parsing failed: {exc}")
            return None

    def _parse_cef(self, text: str) -> dict | None:
        """
        Parses CEF (Common Event Format) — used by ArcSight and enterprise SIEMs.

        Format:
            CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|EventClassId|Name|Severity|[Extension]

        Severity: 0–3=low, 4–6=medium, 7–8=high, 9–10=critical  (or text labels)
        Standard extension fields mapped: src→source_ip, suser→user, rt→timestamp
        Epoch-millisecond timestamps (13-digit) are converted to ISO 8601.
        """
        match = _CEF_RE.match(text)
        if not match:
            return None

        gd = match.groupdict()

        # Map CEF severity (numeric 0–10 or text label)
        cef_sev = gd["severity"].strip().lower()
        if cef_sev.isdigit():
            sev_int = int(cef_sev)
            if sev_int <= 3:
                severity = "low"
            elif sev_int <= 6:
                severity = "medium"
            elif sev_int <= 8:
                severity = "high"
            else:
                severity = "critical"
        else:
            severity = self._CEF_SEVERITY_MAP.get(cef_sev, "low")

        # Parse extension key=value pairs
        extensions: dict = {}
        for m in _KV_PAIR_RE.finditer(gd.get("extensions", "")):
            key = m.group(1)
            value = m.group(2) or m.group(3) or m.group(4) or ""
            extensions[key] = value

        # Map CEF standard extension fields → SOC schema fields
        source_ip = extensions.get("src") or extensions.get("sourceAddress")
        user = (
            extensions.get("suser")
            or extensions.get("sourceUserName")
            or extensions.get("duser")
        )
        timestamp = (
            extensions.get("rt")
            or extensions.get("deviceReceiptTime")
            or extensions.get("end")
        )

        # Convert 13-digit epoch-ms timestamp to ISO 8601
        if timestamp and str(timestamp).isdigit() and len(str(timestamp)) == 13:
            try:
                ts_dt = datetime.fromtimestamp(int(timestamp) / 1000, tz=timezone.utc)
                timestamp = ts_dt.isoformat()
            except Exception:
                pass

        vendor = gd["vendor"].strip()
        product = gd["product"].strip()

        result: dict = {
            "source": f"cef-{vendor}-{product}".lower().replace(" ", "-"),
            "event_type": f"cef_{gd['event_id']}".lower().replace(" ", "_"),
            "message": gd["name"].strip() or f"CEF event {gd['event_id']} from {vendor}",
            "severity": severity,
            "source_ip": source_ip or None,
            "user": user or None,
            "metadata": {
                "cef_version": gd["cef_version"],
                "vendor": vendor,
                "product": product,
                "device_version": gd["dev_version"],
                "event_id": gd["event_id"],
                "extensions": extensions,
                "format": "cef",
            },
        }
        if timestamp:
            result["timestamp"] = timestamp

        return result

    def _parse_leef(self, text: str) -> dict | None:
        """
        Parses LEEF (Log Event Extended Format) — used by IBM QRadar.

        Format:
            LEEF:Version|Vendor|Product|Version|EventID|[Attributes]

        Attributes are tab-separated key=value pairs (LEEF 2.0)
        or space-separated key=value pairs (LEEF 1.0 fallback).
        Standard fields mapped: src/srcip→source_ip, usrName→user, devTime→timestamp
        """
        match = _LEEF_RE.match(text)
        if not match:
            return None

        gd = match.groupdict()
        attr_str = gd.get("attributes", "")

        # Parse attributes: tab-separated (LEEF 2.0) preferred, then regex KV fallback
        attributes: dict = {}
        if "\t" in attr_str:
            for pair in attr_str.split("\t"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    attributes[k.strip()] = v.strip()
        else:
            for m in _KV_PAIR_RE.finditer(attr_str):
                key = m.group(1)
                value = m.group(2) or m.group(3) or m.group(4) or ""
                attributes[key] = value

        # Map LEEF standard fields → SOC schema
        source_ip = (
            attributes.get("src")
            or attributes.get("srcip")
            or attributes.get("sourceip")
        )
        user = (
            attributes.get("usrName")
            or attributes.get("suser")
            or attributes.get("user")
        )
        severity_raw = attributes.get("sev") or attributes.get("severity") or "low"
        timestamp = (
            attributes.get("devTime")
            or attributes.get("startTime")
            or attributes.get("endTime")
        )

        # Map severity: numeric or text
        if str(severity_raw).isdigit():
            s = int(severity_raw)
            severity = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
        else:
            sev_lower = str(severity_raw).lower()
            severity = sev_lower if sev_lower in ("low", "medium", "high", "critical") else "low"

        vendor = gd["vendor"].strip()
        product = gd["product"].strip()
        event_id = gd["event_id"].strip()

        result: dict = {
            "source": f"leef-{vendor}-{product}".lower().replace(" ", "-"),
            "event_type": f"leef_{event_id}".lower().replace(" ", "_"),
            "message": f"LEEF event {event_id} from {vendor} {product}",
            "severity": severity,
            "source_ip": source_ip or None,
            "user": user or None,
            "metadata": {
                "leef_version": gd["leef_version"],
                "vendor": vendor,
                "product": product,
                "device_version": gd["dev_version"],
                "event_id": event_id,
                "attributes": attributes,
                "format": "leef",
            },
        }
        if timestamp:
            result["timestamp"] = timestamp

        return result

    def _parse_key_value(self, text: str) -> dict | None:
        """
        Parses generic key=value log lines (Cisco ASA, Palo Alto, firewall logs).

        Guards against false-positives:
          - Requires ≥2 key=value pairs
          - Requires at least one recognized SOC-relevant field name
            (src, dst, action, user, host, event, severity, etc.)
        """
        matches = list(_KV_PAIR_RE.finditer(text))
        if len(matches) < 2:
            return None

        pairs: dict = {}
        for m in matches:
            key = m.group(1).lower()
            value = m.group(2) or m.group(3) or m.group(4) or ""
            pairs[key] = value

        # Must contain at least one recognized SOC field
        _SOC_FIELDS = {
            "src", "dst", "action", "user", "host", "event", "type",
            "severity", "level", "proto", "dport", "sport", "msg",
            "reason", "ip", "timestamp", "srcip", "dstip", "username",
            "device", "facility", "alert", "category",
        }
        if not (_SOC_FIELDS & set(pairs.keys())):
            return None

        # Extract and map standard fields
        source_ip = pairs.get("src") or pairs.get("srcip") or pairs.get("sourceip")
        user = pairs.get("user") or pairs.get("username") or pairs.get("suser")
        severity_raw = pairs.get("severity") or pairs.get("level") or pairs.get("sev") or "low"
        sev_lower = str(severity_raw).lower()
        severity = sev_lower if sev_lower in ("low", "medium", "high", "critical") else "low"
        event_type = (
            pairs.get("event") or pairs.get("type") or pairs.get("action") or "kv_event"
        )
        source = pairs.get("host") or pairs.get("device") or pairs.get("facility") or "kv-source"
        message = (
            pairs.get("msg")
            or pairs.get("message")
            or pairs.get("reason")
            or pairs.get("alert")
            or f"Key-Value log event: {event_type}"
        )
        timestamp = pairs.get("timestamp") or pairs.get("time") or pairs.get("datetime")

        result: dict = {
            "source": source,
            "event_type": event_type.lower().replace(" ", "_"),
            "message": message,
            "severity": severity,
            "source_ip": source_ip or None,
            "user": user or None,
            "metadata": {
                "raw_pairs": pairs,
                "format": "key_value",
            },
        }
        if timestamp:
            result["timestamp"] = timestamp

        return result

    def _parse_csv(self, text: str) -> dict | None:
        """
        Parses CSV-formatted security log lines (EDR, antivirus tools).

        Strict guards to avoid false-positives:
          - Requires ≥3 commas (≥4 fields)
          - First field MUST be a parseable ISO 8601 timestamp (anchor check)
          - Natural language sentence prefixes are rejected

        Column convention assumed:
            [0] timestamp, [1] source, [2] event_type, [3] severity, [4] message, ...
        """
        if text.count(",") < 3:
            return None

        # Reject natural language sentences
        if any(text.startswith(p) for p in ("The ", "A ", "An ", "This ", "Error ", "Warning ")):
            return None

        try:
            reader = csv.reader(io.StringIO(text))
            rows = list(reader)
            if not rows or not rows[0]:
                return None

            fields = [f.strip() for f in rows[0]]
            if len(fields) < 4:
                return None

            # Anchor: first field must be a valid ISO timestamp
            timestamp = None
            try:
                ts_raw = fields[0].replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts_raw)
                timestamp = dt.isoformat()
            except (ValueError, AttributeError):
                return None  # Strict: skip if no timestamp anchor

            source = fields[1] if len(fields) > 1 else "csv-source"
            event_type = (
                fields[2].lower().replace(" ", "_") if len(fields) > 2 else "csv_log_event"
            )

            severity_raw = fields[3].strip().lower() if len(fields) > 3 else "low"
            severity = severity_raw if severity_raw in ("low", "medium", "high", "critical") else "low"

            message = fields[4] if len(fields) > 4 else text[:200]

            return {
                "source": source,
                "event_type": event_type or "csv_log_event",
                "message": message,
                "severity": severity,
                "timestamp": timestamp,
                "metadata": {
                    "csv_fields": fields,
                    "field_count": len(fields),
                    "format": "csv",
                },
            }

        except Exception:
            return None

    # ─── Syslog Parsers ──────────────────────────────────────────────────────

    def _parse_syslog(self, text: str) -> dict | None:
        # Try RFC 5424 first (more specific — has version number "1")
        match = _SYSLOG_5424_RE.match(text)
        if match:
            gd = match.groupdict()
            pri = int(gd["pri"])
            facility = pri // 8
            severity = pri % 8

            sev_str = "low"
            if severity <= 2:
                sev_str = "critical"
            elif severity == 3:
                sev_str = "high"
            elif severity == 4:
                sev_str = "medium"

            return {
                "source": gd["app_name"] if gd["app_name"] != "-" else "syslog",
                "host": gd["host"] if gd["host"] != "-" else None,
                "event_type": gd["msgid"] if gd["msgid"] != "-" else "syslog_event",
                "message": gd["message"].strip(),
                "timestamp": gd["timestamp"],
                "severity": sev_str,
                "metadata": {
                    "facility": facility,
                    "severity_code": severity,
                    "procid": gd["procid"],
                    "structured_data": gd["structured_data"],
                },
            }

        # Try RFC 3164
        match = _SYSLOG_3164_RE.match(text)
        if match:
            gd = match.groupdict()
            pri = int(gd["pri"])
            facility = pri // 8
            severity = pri % 8

            sev_str = "low"
            if severity <= 2:
                sev_str = "critical"
            elif severity == 3:
                sev_str = "high"
            elif severity == 4:
                sev_str = "medium"

            # RFC 3164 timestamps have no year — inject current year
            raw_ts = gd["timestamp"]
            iso_ts = None
            try:
                current_year = datetime.now().year
                normalized_ts = " ".join(raw_ts.split())
                dt = datetime.strptime(f"{current_year} {normalized_ts}", "%Y %b %d %H:%M:%S")
                iso_ts = dt.replace(tzinfo=timezone.utc).isoformat()
            except Exception:
                iso_ts = None

            result = {
                "source": gd["tag"],
                "host": gd["host"],
                "event_type": "syslog_event",
                "message": gd["message"].strip(),
                "severity": sev_str,
                "metadata": {
                    "facility": facility,
                    "severity_code": severity,
                    "pid": gd["pid"],
                    "raw_timestamp": raw_ts,
                },
            }
            if iso_ts:
                result["timestamp"] = iso_ts
            return result

        return None

    # ─── Web Log Parser ───────────────────────────────────────────────────────

    def _parse_web(self, text: str) -> dict | None:
        match = _WEB_LOG_RE.match(text)
        if match:
            gd = match.groupdict()
            status = int(gd["status"])

            sev_str = "low"
            if status >= 500:
                sev_str = "high"
            elif status >= 400:
                sev_str = "medium"

            # Convert CLF timestamp [DD/Mon/YYYY:HH:MM:SS ±HHMM] → ISO 8601
            timestamp_str = gd["timestamp"]
            try:
                dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
                iso_ts = dt.isoformat()
            except Exception:
                iso_ts = timestamp_str

            return {
                "source": "web-server",
                "event_type": f"http_{gd['method'].lower()}",
                "message": f"{gd['method']} {gd['request']} -> {status}",
                "source_ip": gd["ip"],
                "user": gd["authuser"] if gd["authuser"] != "-" else None,
                "severity": sev_str,
                "timestamp": iso_ts,
                "metadata": {
                    "status_code": status,
                    "bytes_sent": gd["bytes"],
                    "referrer": gd["referrer"],
                    "user_agent": gd["user_agent"],
                },
            }
        return None


parsing_service = ParsingService()
