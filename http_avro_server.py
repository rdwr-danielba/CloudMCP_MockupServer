#!/usr/bin/env python3
"""
Python HTTP/S Avro Server
Handles schema validation, decompression of HTTP payloads (auto-detects
zlib / gzip / raw-deflate), configurable logging, custom response action
modes (allow/deny/report-only), optional chunked responses, optional
modified_data for allow responses, and HTTPS with mutual TLS (mTLS).
"""

import sys
import os
import io
import zlib
import gzip
import socket
import ssl
try:
    import zstandard
except ImportError:
    zstandard = None
import datetime
import argparse
import subprocess
import re
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import fastavro

REQUEST_SCHEMA = {
    "type": "record",
    "name": "ExamineRequest",
    "fields": [
        {
            "name": "direction",
            "type": {
                "type": "enum",
                "name": "Direction",
                "symbols": ["request", "response"],
            },
        },
        {
            "name": "data",
            "type": "bytes",
            "doc": "Compressed raw HTTP request or response payload.",
        },
    ],
}

RESPONSE_SCHEMA = {
    "type": "record",
    "name": "ExamineResponse",
    "fields": [
        {
            "name": "action",
            "type": {
                "type": "enum",
                "name": "Action",
                "symbols": ["allow", "deny"],
            },
        },
        {
            "name": "violation_id",
            "type": ["null", "string"],
            "default": None,
        },
        {
            "name": "modified_data",
            "type": ["null", "bytes"],
            "default": None,
            "doc": "Compressed replacement raw HTTP payload.",
        },
    ],
}

PARSED_REQUEST_SCHEMA = fastavro.parse_schema(REQUEST_SCHEMA)
PARSED_RESPONSE_SCHEMA = fastavro.parse_schema(RESPONSE_SCHEMA)

MAX_LOG_BYTES = 2 * 1024 * 1024
HTTP_CHUNK_SIZE = 4096

# Errors raised when the peer has closed/reset the TCP connection (or the TLS
# session) before we finished writing a response. These are expected under
# high traffic (client timeouts, load balancer resets, etc.) and should be
# logged briefly rather than crashing the worker thread with a full traceback.
CONNECTION_ERRORS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, ssl.SSLError)

# Serializes writes to the shared log file across worker threads so concurrent
# requests cannot interleave partial log entries.
_LOG_WRITE_LOCK = threading.Lock()
ALLOW_MODIFIED_HEADER_NAME = b"X-RDWR-CHANGED-REQ"
ALLOW_MODIFIED_HEADER_LINE = b"X-RDWR-CHANGED-REQ: True"
ALLOW_MODIFIED_BODY_MARKER = b"\r\nBODY WAS MODIFIED"
# MCPP decisions use pass plus an optional violation ID / Modify flag, or block.
ACTION_HEADER_NAME = "X-Rdwr-Action"
VIOLATION_ID_HEADER_NAME = "X-RDWR-VIOLATION-ID"
MODIFY_HEADER_NAME = "X-Rdwr-Modify"
VIOLATION_ID = "mccp injection"

# ---------------------------------------------------------------------------
# Selective block-by-inner-header
#
# Blocking is decided by inspecting the ACTUAL HTTP request that the client
# sent to the PSSLO (the decompressed Avro payload), NOT the outer Avro
# transport headers. This lets the SAME PSSLO carry both legit AND attack
# traffic: a request is DENIED only when it carries a special marker header
# that a normal CURL command would never send. Every other request on that
# same PSSLO is ALLOWED. This replaces the fixed --action allow/deny behavior
# whenever --deny-header is configured.
#
# Default marker header (does not exist in a plain CURL request):
#   X-RDWR-Attack: 1
# The header NAME is what matters; its value is ignored, e.g. both
#   curl ... -H "X-RDWR-Attack: 1"
#   curl ... -H "X-RDWR-Attack: anything"
# are treated as attack traffic.
# ---------------------------------------------------------------------------
DEFAULT_DENY_HEADER_NAME = "X-RDWR-Attack"


def inner_request_has_header(raw_http_request, header_name):
    """Return True if the raw (decompressed) HTTP request contains header_name.

    Matching is case-insensitive and only looks at header lines (start of line
    up to the ':'). Supports both CRLF and LF-only header blocks.
    """
    if not isinstance(raw_http_request, (bytes, bytearray)) or not header_name:
        return False

    target = header_name.strip().lower().encode("ascii", "ignore")
    if not target:
        return False

    # Isolate the header block (everything before the body separator).
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw_http_request.find(sep)
        if idx != -1:
            header_block = raw_http_request[:idx]
            break
    else:
        header_block = raw_http_request

    for line in header_block.replace(b"\r\n", b"\n").split(b"\n"):
        name = line.split(b":", 1)[0].strip().lower()
        if name == target:
            return True
    return False

# ---------------------------------------------------------------------------
# Compression format handling
#
# NOTE: After an ADC image upgrade, the compression method used for MCPP
# payloads may change (e.g. zlib -> raw deflate, or zlib -> gzip). Rather than
# hardcoding a single format and breaking again on the next change, this
# decompressor auto-detects the format by inspecting the leading bytes /
# trying each method in turn. Set FORCE_COMPRESSION_FORMAT below if you want
# to pin a single known format instead (e.g. after confirming with the ADC
# side exactly what changed).
# ---------------------------------------------------------------------------

# Set to one of: None (auto-detect), "zlib", "gzip", "raw_deflate"
FORCE_COMPRESSION_FORMAT = None


def decompress_payload(compressed_data):
    """
    Decompress a payload whose exact compression format may vary
    (standard zlib-wrapped deflate, raw/headerless deflate, or gzip).

    Returns: (uncompressed_bytes, format_name_used)
    Raises: ValueError if no supported format could decompress the data.
    """
    if FORCE_COMPRESSION_FORMAT == "zlib":
        return zlib.decompress(compressed_data), "zlib"
    if FORCE_COMPRESSION_FORMAT == "gzip":
        return gzip.decompress(compressed_data), "gzip"
    if FORCE_COMPRESSION_FORMAT == "raw_deflate":
        return zlib.decompress(compressed_data, wbits=-zlib.MAX_WBITS), "raw_deflate"

    errors = []

    # 0) Zstandard (magic bytes: 0x28 0xB5 0x2F 0xFD). Checked first since it
    # has a distinctive signature and is cheap to rule in/out up front.
    ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
    if compressed_data[:4] == ZSTD_MAGIC:
        if zstandard is None:
            errors.append(
                "zstd: data appears to be zstd-compressed (magic bytes matched) "
                "but the 'zstandard' package is not installed "
                "(pip install zstandard --break-system-packages)"
            )
        else:
            try:
                return zstandard.ZstdDecompressor().decompress(compressed_data), "zstd"
            except Exception as e:
                errors.append(f"zstd: {e}")

    # 1) Standard zlib (RFC 1950: 2-byte header + deflate + adler32 checksum)
    try:
        return zlib.decompress(compressed_data), "zlib"
    except Exception as e:
        errors.append(f"zlib: {e}")

    # 2) gzip (RFC 1952: 10-byte header, magic bytes 0x1f 0x8b)
    try:
        return gzip.decompress(compressed_data), "gzip"
    except Exception as e:
        errors.append(f"gzip: {e}")

    # 3) Raw / headerless deflate (RFC 1951, no zlib or gzip wrapper)
    try:
        return zlib.decompress(compressed_data, wbits=-zlib.MAX_WBITS), "raw_deflate"
    except Exception as e:
        errors.append(f"raw_deflate: {e}")

    # 4) Zstandard fallback, tried even if the magic-byte check above didn't
    # match (in case of a non-standard/framed variant).
    if zstandard is not None and compressed_data[:4] != ZSTD_MAGIC:
        try:
            return zstandard.ZstdDecompressor().decompress(compressed_data), "zstd"
        except Exception as e:
            errors.append(f"zstd (fallback): {e}")

    raise ValueError(
        "Failed to decompress data using zstd, zlib, gzip, or raw deflate. "
        + " | ".join(errors)
    )


def compress_payload(data, fmt="zlib"):
    """Compress data using the given format ("zlib", "gzip", "raw_deflate", or "zstd")."""
    if fmt == "zlib":
        return zlib.compress(data)
    if fmt == "gzip":
        return gzip.compress(data)
    if fmt == "raw_deflate":
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        return compressor.compress(data) + compressor.flush()
    if fmt == "zstd":
        if zstandard is None:
            raise ValueError("zstd compression requested but 'zstandard' package is not installed.")
        return zstandard.ZstdCompressor().compress(data)
    raise ValueError(f"Unknown compression format: {fmt}")


def decode_avro_request(body_bytes):
    """
    Decodes client Avro request. Supports both Object Container File format
    and schemaless binary encoding.
    Returns: (record_dict, was_container)
    """
    container_error = None
    schemaless_error = None

    try:
        fo = io.BytesIO(body_bytes)
        reader = fastavro.reader(fo)
        records = list(reader)
        if records:
            return records[0], True
        container_error = "container Avro contained no records"
    except Exception as e:
        container_error = str(e)

    try:
        fo = io.BytesIO(body_bytes)
        record = fastavro.schemaless_reader(fo, PARSED_REQUEST_SCHEMA)
        return record, False
    except Exception as e:
        schemaless_error = str(e)

    raise ValueError(
        "Failed to decode Avro body. "
        f"Container decode error: {container_error}. "
        f"Schemaless decode error: {schemaless_error}."
    )


def encode_avro_response(record, use_container=False):
    """Encodes response to binary Avro."""
    fo = io.BytesIO()
    if use_container:
        fastavro.writer(fo, PARSED_RESPONSE_SCHEMA, [record])
    else:
        fastavro.schemaless_writer(fo, PARSED_RESPONSE_SCHEMA, record)
    return fo.getvalue()


def add_allow_modified_header(raw_http_request):
    """
    Return a modified copy of the raw uncompressed HTTP request with:
        X-RDWR-CHANGED-REQ: True

    If the request has a non-empty body, append BODY WAS MODIFIED to the end
    of the body and keep Content-Length in sync when present.

    If the header already exists, its value is replaced with True.
    Supports CRLF and LF-only HTTP header blocks. If no header/body separator
    is found, the header is appended after the available bytes using CRLF.
    """
    if not isinstance(raw_http_request, bytes):
        raise ValueError("Cannot modify allow response: uncompressed request data is not bytes.")

    if b"\r\n\r\n" in raw_http_request:
        sep = b"\r\n\r\n"
        newline = b"\r\n"
    elif b"\n\n" in raw_http_request:
        sep = b"\n\n"
        newline = b"\n"
    else:
        # Best-effort fallback for malformed/raw data without an HTTP header terminator.
        return raw_http_request.rstrip(b"\r\n") + b"\r\n" + ALLOW_MODIFIED_HEADER_LINE + b"\r\n\r\n"

    header_block, body = raw_http_request.split(sep, 1)
    lines = header_block.split(newline)
    output_lines = []
    replaced = False
    content_length_updated = False
    body_modified = body

    if body:
        body_modified = body + ALLOW_MODIFIED_BODY_MARKER
        content_length_line = f"Content-Length: {len(body_modified)}".encode("ascii")
    else:
        content_length_line = None

    for line in lines:
        # Replace existing X-RDWR-CHANGED-REQ header value (keep single header)
        if line.lower().startswith(ALLOW_MODIFIED_HEADER_NAME.lower() + b":"):
            if not replaced:
                output_lines.append(ALLOW_MODIFIED_HEADER_LINE)
                replaced = True
            # Drop duplicate existing X-RDWR-CHANGED-REQ headers.
        # If original request had an Expect: 100-continue header, drop it from the
        # modified data so the receiver won't attempt the 100-continue handshake.
        elif line.lower().startswith(b"expect:"):
            if b"100-continue" in line.lower():
                # skip this header (remove it)
                continue
            else:
                output_lines.append(line)
        elif content_length_line is not None and line.lower().startswith(b"content-length:"):
            if not content_length_updated:
                output_lines.append(content_length_line)
                content_length_updated = True
            # Drop duplicate existing Content-Length headers.
        else:
            output_lines.append(line)

    if not replaced:
        output_lines.append(ALLOW_MODIFIED_HEADER_LINE)

    if content_length_line is not None and not content_length_updated:
        output_lines.append(content_length_line)

    return newline.join(output_lines) + sep + body_modified


def _safe_header_items(incoming_headers):
    if incoming_headers is None:
        return []
    try:
        return list(incoming_headers.items())
    except Exception:
        return [("<headers>", str(incoming_headers))]


def _format_bytes_for_log(data, label="DATA", max_bytes=MAX_LOG_BYTES):
    if data is None:
        return "(not available)\n"
    if not isinstance(data, bytes):
        return f"{data}\n"

    original_len = len(data)
    truncated = data[:max_bytes]
    was_truncated = original_len > max_bytes

    out = [f"({label}: {original_len} bytes"]
    if was_truncated:
        out.append(f", showing first {max_bytes} bytes")
    out.append(")\n")

    try:
        decoded_str = truncated.decode("utf-8")
        out.append(decoded_str)
        if decoded_str and not decoded_str.endswith("\n"):
            out.append("\n")
    except UnicodeDecodeError:
        out.append("(Binary data, hex representation)\n")
        out.append(truncated.hex())
        out.append("\n")

    if was_truncated:
        out.append(f"... TRUNCATED {original_len - max_bytes} BYTES ...\n")
    return "".join(out)


def _format_record_for_log(record):
    if record is None:
        return "(not available)\n"
    if not isinstance(record, dict):
        return f"{record}\n"

    lines = []
    for key, value in record.items():
        if isinstance(value, bytes):
            lines.append(f"{key}: <bytes length={len(value)}>")
        else:
            lines.append(f"{key}: {value!r}")
    return "\n".join(lines) + "\n"


def write_request_log(
    log_path,
    client_address,
    incoming_headers,
    status,
    failure_reason=None,
    raw_body=None,
    decoded_record=None,
    uncompressed_data=None,
    modified_allow_data=None,
    method=None,
    path=None,
    compression_format=None,
):
    """Append success/failure request details to the configured log file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    client_host = client_address[0] if client_address else "unknown"
    client_port = client_address[1] if client_address and len(client_address) > 1 else "unknown"

    # Build the full entry in memory first so the lock/file is held only for a
    # single write() call, minimizing contention between concurrent request threads.
    parts = []
    parts.append("==================================================\n")
    parts.append(f"=== REQUEST {status} {timestamp} from {client_host}:{client_port} ===\n")
    if method or path:
        parts.append(f"Method: {method or '(unknown)'}\n")
        parts.append(f"Path: {path or '(unknown)'}\n")

    if status == "FAILURE":
        parts.append("\n--- FAILURE REASON ---\n")
        parts.append(f"{failure_reason or '(no failure reason provided)'}\n")

    parts.append("\n--- INCOMING HTTP REQUEST HEADERS ---\n")
    header_items = _safe_header_items(incoming_headers)
    if header_items:
        for key, value in header_items:
            parts.append(f"{key}: {value}\n")
    else:
        parts.append("(no headers available)\n")

    if status == "FAILURE":
        parts.append("\n--- RAW REQUEST BODY AS RECEIVED ---\n")
        parts.append(_format_bytes_for_log(raw_body, label="RAW BODY"))

    if decoded_record is not None:
        parts.append("\n--- DECODED AVRO RECORD ---\n")
        parts.append(_format_record_for_log(decoded_record))

    if compression_format is not None:
        parts.append(f"\n--- DETECTED COMPRESSION FORMAT: {compression_format} ---\n")

    if uncompressed_data is not None:
        parts.append("\n--- DECOMPRESSED AVRO PAYLOAD DATA ---\n")
        parts.append(_format_bytes_for_log(uncompressed_data, label="DECOMPRESSED DATA"))

    if modified_allow_data is not None:
        parts.append("\n--- ALLOW MODIFIED_DATA PAYLOAD BEFORE COMPRESSION ---\n")
        parts.append(_format_bytes_for_log(modified_allow_data, label="ALLOW MODIFIED DATA"))

    parts.append("==================================================\n\n")
    entry = "".join(parts)

    try:
        with _LOG_WRITE_LOCK:
            log_dir = os.path.dirname(log_path)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)

            with open(log_path, "a", encoding="utf-8", errors="replace") as log_file:
                log_file.write(entry)
    except Exception as e:
        print(f"[-] Error writing to log file '{log_path}': {e}", file=sys.stderr)


class AvroHTTPRequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP request handler for validating and processing Avro schemas."""

    protocol_version = "HTTP/1.1"
    # Avoid Nagle's algorithm delays on small Avro request/response payloads.
    disable_nagle_algorithm = True

    def log_message(self, format, *args):
        pass

    def resolve_action(self, uncompressed_data=None):
        """Decide the effective action ("allow"/"report-only"/"deny").

        When --deny-header is configured (default: X-RDWR-Attack) the server
        runs in selective mode and inspects the ACTUAL HTTP request the client
        sent to the PSSLO (the decompressed Avro payload). The decision is:

          * DENY (block)       -> inner request carries the marker header
                                  (attack traffic).
          * REPORT-ONLY (pass) -> legit traffic (no marker header) AND a
                                  non-empty X-RDWR-VIOLATION-ID is configured
                                  (--violation-id=<value>): the request is
                                  passed but reported (not enforced).
          * ALLOW (pass)       -> legit traffic (no marker header) AND the
                                  violation ID is empty/omitted.

        This lets the SAME PSSLO carry legit (allow/report-only) and attack
        (block) traffic. When selective mode is disabled, the global --action
        is used.
        """
        deny_header = getattr(self.server, "config_deny_header", None)
        if not deny_header:
            return self.server.config_action

        has_marker = inner_request_has_header(uncompressed_data, deny_header)
        if has_marker:
            action = "deny"
        else:
            # Legit traffic: report-only when a non-empty violation ID is
            # configured, otherwise a plain allow.
            violation_id = self.server.config_violation_id
            if violation_id:
                action = "report-only"
            else:
                action = "allow"

        print(
            f"[+] Selective action: inner header {deny_header!r} "
            f"{'FOUND' if has_marker else 'not found'} -> {action.upper()} "
            f"(client {self.client_address[0]}:{self.client_address[1]})"
        )
        return action

    def do_POST(self):
        body_bytes = None
        record = None
        uncompressed_data = None
        modified_allow_data = None
        was_container = False
        compression_format = None

        try:
            raw_content_length = self.headers.get("Content-Length")
            if raw_content_length is None:
                raise ValueError("Missing Content-Length header.")

            try:
                content_length = int(raw_content_length)
            except ValueError:
                raise ValueError(f"Invalid Content-Length header: {raw_content_length!r}.")

            if content_length <= 0:
                raise ValueError("Missing or empty Content-Length header.")

            try:
                body_bytes = self.rfile.read(content_length)
            except Exception as e:
                raise ValueError(f"Failed to read request body: {e}")

            if len(body_bytes) != content_length:
                raise ValueError(
                    f"Incomplete request body: expected {content_length} bytes, "
                    f"received {len(body_bytes)} bytes."
                )

            record, was_container = decode_avro_request(body_bytes)

            if not isinstance(record, dict):
                raise ValueError("Avro body must be a Record dictionary.")
            if "direction" not in record or "data" not in record:
                raise ValueError("Avro body missing required fields 'direction' or 'data'.")

            direction = record["direction"]
            if direction != "request":
                raise ValueError(f"Validation failed: direction must be 'request', got '{direction}'.")

            compressed_data = record["data"]
            if not isinstance(compressed_data, bytes):
                raise ValueError("Avro data field must be of type 'bytes'.")

            try:
                uncompressed_data, compression_format = decompress_payload(compressed_data)
                print(
                    f"[+] Compression format detected: "
                    f"{compression_format}"
                )
                print(
                    f"[+] Payload compression detected: "
                    f"{compression_format} "
                    f"(compressed={len(compressed_data)} bytes, "
                    f"uncompressed={len(uncompressed_data)} bytes)"
                )
            except Exception as e:
                first16 = compressed_data[:16].hex()
                first32 = compressed_data[:32].hex()
                raise ValueError(
                    f"Failed to decompress data. "
                    f"First16={first16} "
                    f"First32={first32} "
                    f"Error={e}"
                )

            # When --deny-header is set, selective mode inspects the inner
            # (decompressed) HTTP request and denies only those carrying the
            # marker header, allowing everything else. Otherwise the global
            # --action is used.
            effective_action = self.resolve_action(uncompressed_data)

            if effective_action == "allow" and self.server.config_allow_modified_data:
                modified_allow_data = add_allow_modified_header(uncompressed_data)

            if not self.server.config_error_log:
                write_request_log(
                    log_path=self.server.config_log_path,
                    client_address=self.client_address,
                    incoming_headers=self.headers,
                    status="SUCCESS",
                    raw_body=body_bytes,
                    decoded_record=record,
                    uncompressed_data=uncompressed_data,
                    modified_allow_data=modified_allow_data,
                    method=self.command,
                    path=self.path,
                    compression_format=compression_format,
                )

            # Respond using the SAME compression format we detected on the way
            # in, so the response round-trips through whatever the ADC side
            # currently expects without needing a separate config flag.
            response_compression_format = compression_format or "zlib"
            violation_id = self.server.config_violation_id

            if effective_action == "deny":
                rdwr_action = "block"
                # In selective mode an allow-defaulted config leaves violation_id
                # as None; fall back to the standard violation ID for blocks.
                if violation_id is None:
                    violation_id = VIOLATION_ID
                block_html = (
                    "<html>\n"
                    "<head><title>403 Forbidden</title></head>\n"
                    "<body style='font-family: sans-serif; text-align: center; margin-top: 100px;'>\n"
                    "<h1>403 Forbidden</h1>\n"
                    "<p>Your request has been blocked by the security system.</p>\n"
                    "</body>\n"
                    "</html>"
                )

                raw_http_response = (
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(block_html.encode('utf-8'))}\r\n"
                    f"{ACTION_HEADER_NAME}: {rdwr_action}\r\n"
                    f"{VIOLATION_ID_HEADER_NAME}: {violation_id}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    f"{block_html}"
                ).encode("utf-8")

                response_record = {
                    "action": "deny",
                    "violation_id": violation_id,
                    "modified_data": compress_payload(raw_http_response, response_compression_format),
                }
            else:
                # Legit traffic. Two sub-cases decided in resolve_action():
                #   * report-only -> a non-empty violation ID is configured, so
                #     the request is PASSED but reported (X-Rdwr-Action: pass +
                #     X-RDWR-VIOLATION-ID set). Not enforced.
                #   * allow       -> violation ID empty/omitted, so the request
                #     is PASSED with no violation reported.
                rdwr_action = "pass"
                if effective_action == "report-only":
                    # Ensure a violation is reported even if selective mode left
                    # the stored config as a falsy/None default.
                    if not violation_id:
                        violation_id = VIOLATION_ID
                    print(
                        f"[+] REPORT-ONLY: passing legit request but reporting "
                        f"violation_id={violation_id!r} "
                        f"(client {self.client_address[0]}:{self.client_address[1]})"
                    )
                else:
                    # Pure allow: never emit a violation header.
                    violation_id = None
                    print(
                        f"[+] ALLOW: passing legit request with no violation "
                        f"(client {self.client_address[0]}:{self.client_address[1]})"
                    )
                response_record = {
                    "action": "allow",
                    "violation_id": violation_id,
                    "modified_data": compress_payload(modified_allow_data, response_compression_format)
                    if modified_allow_data is not None
                    else None,
                }

            response_bytes = encode_avro_response(response_record, use_container=was_container)

            # Outer HTTP headers the caller uses to decide enforce vs. report-only.
            response_headers = [(ACTION_HEADER_NAME, rdwr_action)]
            if violation_id is not None:
                response_headers.append((VIOLATION_ID_HEADER_NAME, violation_id))
            if self.server.config_modify is not None:
                response_headers.append((MODIFY_HEADER_NAME, self.server.config_modify))

            if self.server.config_chunked:
                self.send_chunked_avro_response(response_bytes, response_headers)
            else:
                self.send_response(200)
                self.send_header("Content-Type", "avro/binary")
                for name, value in response_headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(response_bytes)))
                self.end_headers()
                self.wfile.write(response_bytes)

        except CONNECTION_ERRORS as e:
            # The client already disconnected (broken pipe / reset / TLS teardown).
            # There is no socket left to answer on, so just record it and move on
            # instead of letting the exception bubble up as an unhandled error.
            err_msg = f"Client disconnected before response could be sent: {e}"
            print(f"[-] {err_msg}", file=sys.stderr)
            write_request_log(
                log_path=self.server.config_log_path,
                client_address=self.client_address,
                incoming_headers=self.headers,
                status="FAILURE",
                failure_reason=err_msg,
                raw_body=body_bytes,
                decoded_record=record,
                uncompressed_data=uncompressed_data,
                modified_allow_data=modified_allow_data,
                method=self.command,
                path=self.path,
                compression_format=compression_format,
            )
        except Exception as e:
            err_msg = f"Inbound Request Error: {e}"
            print(f"[-] {err_msg}", file=sys.stderr)
            write_request_log(
                log_path=self.server.config_log_path,
                client_address=self.client_address,
                incoming_headers=self.headers,
                status="FAILURE",
                failure_reason=err_msg,
                raw_body=body_bytes,
                decoded_record=record,
                uncompressed_data=uncompressed_data,
                modified_allow_data=modified_allow_data,
                method=self.command,
                path=self.path,
                compression_format=compression_format,
            )
            try:
                self.send_error_response(err_msg)
            except CONNECTION_ERRORS as write_err:
                # Connection dropped while trying to report the original error.
                # Nothing more we can do; avoid raising out of do_POST.
                print(f"[-] Client disconnected while sending error response: {write_err}", file=sys.stderr)

    def do_GET(self):
        err_msg = "Method not allowed. Use POST with Avro binary payload."
        print(f"[-] Inbound Request Error: {err_msg}", file=sys.stderr)
        write_request_log(
            log_path=self.server.config_log_path,
            client_address=self.client_address,
            incoming_headers=self.headers,
            status="FAILURE",
            failure_reason=err_msg,
            raw_body=None,
            decoded_record=None,
            uncompressed_data=None,
            modified_allow_data=None,
            method=self.command,
            path=self.path,
        )
        try:
            self.send_error_response(err_msg)
        except CONNECTION_ERRORS as write_err:
            print(f"[-] Client disconnected while sending error response: {write_err}", file=sys.stderr)

    def send_chunked_avro_response(self, response_bytes, response_headers):
        """
        Send the Avro response payload using HTTP chunked transfer encoding.

        The Avro bytes are unchanged. Only the outer HTTP response uses chunked
        framing instead of Content-Length. Used when --chunked is enabled, for any action.
        """
        self.send_response(200)
        self.send_header("Content-Type", "avro/binary")
        for name, value in response_headers:
            self.send_header(name, value)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        for offset in range(0, len(response_bytes), HTTP_CHUNK_SIZE):
            chunk = response_bytes[offset:offset + HTTP_CHUNK_SIZE]
            self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii"))
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")

        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def send_error_response(self, message):
        self.send_response(400)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        err_bytes = message.encode("utf-8")
        self.send_header("Content-Length", str(len(err_bytes)))
        self.end_headers()
        self.wfile.write(err_bytes)


class AvroThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that logs client disconnects (broken pipe/reset,
    TLS teardown) concisely instead of dumping a full traceback for every
    occurrence, which floods the logs under high traffic. Any other,
    unexpected error still gets the normal full traceback."""

    # TCPServer defaults this to 5. A small accept queue can overflow during
    # bursts, especially when TLS handshakes are in progress, causing the
    # kernel to reject new connections before Python can log them.
    request_queue_size = socket.SOMAXCONN
    daemon_threads = True

    def get_request(self):
        """Accept a socket and defer TLS handshaking to its worker thread.

        Wrapping the listening socket with ``SSLContext.wrap_socket`` makes
        ``SSLSocket.accept`` perform the TLS handshake in the server's main
        accept loop. One slow client can then prevent the loop from accepting
        other sockets and fill the listen queue. Wrapping each accepted socket
        with ``do_handshake_on_connect=False`` keeps accept non-blocking; the
        first read in the request worker performs the handshake instead.
        """
        request, client_address = self.socket.accept()
        ssl_context = getattr(self, "ssl_context", None)
        if ssl_context is None:
            return request, client_address

        try:
            request = ssl_context.wrap_socket(
                request,
                server_side=True,
                do_handshake_on_connect=False,
            )
        except Exception:
            request.close()
            raise
        return request, client_address

    def handle_error(self, request, client_address):
        exc_value = sys.exc_info()[1]
        if isinstance(exc_value, CONNECTION_ERRORS):
            print(
                f"[-] Client {client_address[0]}:{client_address[1]} disconnected: {exc_value}",
                file=sys.stderr,
            )
            return
        super().handle_error(request, client_address)


def generate_certificates():
    """Generate a self-signed CA, server certificate, and client certificate."""
    print("[*] Generating certificates/keys in 'certs' folder...")
    os.makedirs("certs", exist_ok=True)

    subprocess.run([
        "openssl", "req", "-x509", "-sha256", "-newkey", "rsa:2048", "-nodes",
        "-keyout", "certs/ca.key", "-out", "certs/ca.crt", "-days", "365",
        "-subj", "/CN=TestCA",
    ], check=True)

    subprocess.run([
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", "certs/server.key", "-out", "certs/server.csr",
        "-subj", "/CN=localhost",
    ], check=True)

    subprocess.run([
        "openssl", "x509", "-req", "-in", "certs/server.csr",
        "-CA", "certs/ca.crt", "-CAkey", "certs/ca.key", "-CAcreateserial",
        "-out", "certs/server.crt", "-days", "365", "-sha256",
    ], check=True)

    subprocess.run([
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", "certs/client.key", "-out", "certs/client.csr",
        "-subj", "/CN=TestClient",
    ], check=True)

    subprocess.run([
        "openssl", "x509", "-req", "-in", "certs/client.csr",
        "-CA", "certs/ca.crt", "-CAkey", "certs/ca.key",
        "-out", "certs/client.crt", "-days", "365", "-sha256",
    ], check=True)

    for temp_file in ["certs/server.csr", "certs/client.csr", "certs/ca.srl"]:
        if os.path.exists(temp_file):
            os.remove(temp_file)

    print("[+] Certificates and test PKI successfully generated in 'certs/'!")
    print("Created files:")
    print("  - [ca.crt]       -> Trust CA Certificate")
    print("  - [ca.key]       -> Trust CA Private Key")
    print("  - [server.crt]   -> Server Certificate")
    print("  - [server.key]   -> Server Private Key")
    print("  - [client.crt]   -> Client Certificate")
    print("  - [client.key]   -> Client Private Key")
    print("\n[+] To start https with mTLS using generated credentials:")
    print("  python3 http_avro_server.py --mode https --cert certs/server.crt --key certs/server.key --mtls --trust-ca certs/ca.crt")


def main():
    parser = argparse.ArgumentParser(
        description="Secure Custom HTTP/S Avro Server with mTLS validation, schema checks and compression support.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--ip", default="0.0.0.0", help="IP address to bind the server to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind the server to (default: 8080)")
    parser.add_argument("--mode", choices=["http", "https"], default="http", help="Protocol mode (default: http)")
    parser.add_argument("--cert", help="Path to server SSL certificate (required for HTTPS)")
    parser.add_argument("--key", help="Path to server SSL private key (required for HTTPS)")
    parser.add_argument("--mtls", action="store_true", help="Enable mutual TLS (request/verify client certificate)")
    parser.add_argument("--trust-ca", help="Path to CA certificate file to validate client cert (required for mTLS)")
    parser.add_argument("--action", choices=["allow", "deny", "report-only"], default="allow", help="Outcome response mode: allow, deny (block), or report-only (pass, reported but not enforced) (default: allow)")
    parser.add_argument(
        "--deny-header",
        default=DEFAULT_DENY_HEADER_NAME,
        help="Selective mode: DENY a request only when its inner (decompressed) HTTP "
             "request carries this header NAME (value ignored); ALLOW everything else. "
             "This lets the same PSSLO carry both legit and attack traffic and replaces "
             f"the fixed --action allow/deny. Default: '{DEFAULT_DENY_HEADER_NAME}'. "
             "Pass an empty string (--deny-header '') to disable selective mode and use --action.",
    )
    parser.add_argument("--chunked", action="store_true", help="Send the Avro response body using HTTP chunked transfer encoding (any --action)")
    parser.add_argument("--allow-modified-data", action="store_true", help="With --action allow, return compressed modified_data containing the original uncompressed request plus header X-RDWR-CHANGED-REQ: True and append BODY WAS MODIFIED to any non-empty body")
    parser.add_argument("--violation-id", help="Override X-RDWR-VIOLATION-ID independently of --action; --violation-id= emits an explicit empty header (default: omitted for allow, mccp injection otherwise)")
    parser.add_argument("--modify", choices=["true", "false"], help="Emit X-Rdwr-Modify independently of --action and replacement data (default: true with --allow-modified-data, omitted otherwise)")
    parser.add_argument("--log", default="server_access.log", help="Path to output full request log file (default: server_access.log)")
    parser.add_argument("--error-log", action="store_true", help="Write only error logs; successful requests are not logged")
    parser.add_argument("--generate-certs", action="store_true", help="Generate helper Root CA / client / server PKI files in 'certs/' and exit")
    parser.add_argument(
        "--compression-format",
        choices=["auto", "zlib", "gzip", "raw_deflate", "zstd"],
        default="auto",
        help="Compression format to expect for incoming payloads (default: auto-detect zlib/gzip/raw_deflate)",
    )

    args = parser.parse_args()

    if args.generate_certs:
        generate_certificates()
        return

    if args.mode == "https":
        if not args.cert or not args.key:
            parser.error("HTTPS mode requires --cert and --key arguments.")

    if args.mtls:
        if args.mode != "https":
            parser.error("mTLS requires HTTPS mode (--mode https).")
        if not args.trust_ca:
            parser.error("mTLS requires a trusted root CA certificate (--trust-ca) to validate client certs.")

    if args.allow_modified_data and args.action != "allow":
        parser.error("--allow-modified-data is only relevant with --action allow.")

    global FORCE_COMPRESSION_FORMAT
    FORCE_COMPRESSION_FORMAT = None if args.compression_format == "auto" else args.compression_format

    # The header NAME whose presence in the inner (decompressed) HTTP request
    # triggers a DENY. Empty/blank disables selective mode (falls back to --action).
    deny_header = (args.deny_header or "").strip() or None

    # ThreadingHTTPServer handles each connection in its own daemon thread so
    # slow/concurrent clients don't block one another (the plain HTTPServer
    # processes requests one at a time on a single thread).
    server = AvroThreadingHTTPServer((args.ip, args.port), AvroHTTPRequestHandler)
    server.config_log_path = args.log
    server.config_error_log = args.error_log
    server.config_action = args.action
    server.config_deny_header = deny_header
    server.config_chunked = args.chunked
    server.config_allow_modified_data = args.allow_modified_data
    # None means omitted, whereas an empty string must remain an explicit header.
    server.config_violation_id = args.violation_id
    # In selective mode (--deny-header active), report-only vs allow is driven
    # SOLELY by --violation-id, so --action must NOT seed a default violation ID
    # (otherwise legit traffic would be classified report-only instead of allow).
    # Only when selective mode is OFF does --action deny/report-only seed the
    # standard violation ID.
    if (
        server.config_violation_id is None
        and deny_header is None
        and args.action != "allow"
    ):
        server.config_violation_id = VIOLATION_ID
    server.config_modify = args.modify
    if server.config_modify is None and args.allow_modified_data:
        server.config_modify = "true"

    protocol_label = "HTTP"
    server.ssl_context = None
    if args.mode == "https":
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

        if args.mtls:
            protocol_label = "HTTPS with mTLS validation"
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            ssl_ctx.load_verify_locations(cafile=args.trust_ca)
        else:
            protocol_label = "HTTPS"
            ssl_ctx.verify_mode = ssl.CERT_NONE

        # Keep the listening socket as a normal TCP socket. The server wraps
        # accepted sockets in get_request(), so a TLS handshake cannot block
        # the main accept loop and starve the TCP listen queue.
        server.ssl_context = ssl_ctx

    print(f"[*] Starting {protocol_label} Avro Server on {args.ip}:{args.port}...")
    print(f"[*] Configured log path: {args.log}")
    if args.error_log:
        print("[*] Successful requests will not be logged.")
    print(f"[*] Default action mode: {args.action.upper()}")
    if deny_header:
        print("[*] Selective deny-by-inner-header mode: ENABLED")
        print(f"[*] Inner HTTP requests containing header '{deny_header}' will be DENIED; "
              f"all others ALLOWED")
    else:
        print("[*] Selective deny-by-inner-header mode: DISABLED "
              f"(using global --action={args.action.upper()})")
    print(f"[*] Chunked responses: {'ENABLED' if args.chunked else 'DISABLED'}")
    print(f"[*] Allow modified_data responses: {'ENABLED' if args.allow_modified_data else 'DISABLED'}")
    print(f"[*] Violation ID header: {server.config_violation_id!r}")
    print(f"[*] Modify header: {server.config_modify or '(missing)'}")
    print(f"[*] Compression format: {args.compression_format.upper()}"
          + (" (auto-detect zlib/gzip/raw_deflate)" if args.compression_format == "auto" else ""))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        server.server_close()
    print("[+] Server stopped.")


if __name__ == "__main__":
    main()
