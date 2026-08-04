import os
import sys
import socket
import zipfile
import tempfile
import shutil
import webbrowser
import json
import csv
import io
import ipaddress
import re
import importlib
import subprocess
import time
import smtplib
import mimetypes
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Timer
from zoneinfo import ZoneInfo
from email.message import EmailMessage

# Backend update notes (today):
# - Index rendering now uses external templates/static assets.
# - SPA flow timeframe filters are parsed as local ISO datetime values.
# - Source-port trace extraction now supports both srcPort and flowSrcPort tokens.
# - Source-port trace extraction now includes multiline continuation blocks.
# - SPA check options support deselect behavior in the UI (label/button toggle off).
# - SPA mode hides and resets the full cached-config option and search controls.
# - Result header supports cached-config and transaction-level download links.
# - Transaction-level initiate-analysis output is scoped to the selected source port.


def ensure_runtime_dependencies():
    auto_install = os.environ.get("DARTHAWK_AUTO_INSTALL", "1").strip().lower() not in {
        "0", "false", "no"
    }
    if not auto_install:
        return

    # Ensure pip is available on both macOS and Windows Python installations.
    try:
        import ensurepip

        ensurepip.bootstrap(upgrade=True)
    except Exception:
        # Continue even if bootstrap is unavailable; pip may already be present.
        pass

    project_requirements = Path(__file__).with_name("requirements.txt")
    pip_command = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"]

    print("[i] Installing runtime dependencies automatically...")
    try:
        if project_requirements.exists():
            subprocess.check_call(pip_command + ["-r", str(project_requirements)])
        else:
            subprocess.check_call(pip_command + ["Flask>=3.0,<4.0"])
    except subprocess.CalledProcessError:
        print("[!] Automatic dependency installation failed.")
        print("[!] Try running manually:")
        print("    - python -m pip install -r requirements.txt")
        print("    - py -m pip install -r requirements.txt   (Windows)")
        sys.exit(1)


ensure_runtime_dependencies()

try:
    from tzlocal.windows_tz import win_tz as WINDOWS_TZLOCAL_MAP
except ImportError:
    WINDOWS_TZLOCAL_MAP = {}

from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
# Max upload size (default 1.5GB / 1536MB) configurable via DARTHAWK_MAX_UPLOAD_MB.
max_upload_mb = int(os.environ.get("DARTHAWK_MAX_UPLOAD_MB", "1536"))
if max_upload_mb <= 0:
    max_upload_mb = 700
app.config['MAX_CONTENT_LENGTH'] = max_upload_mb * 1024 * 1024


def get_large_bundle_preview_threshold_mb():
    threshold_raw = os.environ.get("DARTHAWK_LARGE_BUNDLE_PREVIEW_MB", "1536").strip()
    try:
        threshold_mb = int(threshold_raw)
    except ValueError:
        threshold_mb = 1536

    if threshold_mb < 1:
        threshold_mb = 1
    return threshold_mb


def find_zta_cached_config_json_files(root_dir):
    json_files = []
    for current_root, _, files in os.walk(root_dir):
        normalized_root = current_root.lower().replace("_", " ")
        if "__macosx" in current_root.lower():
            continue
        has_required_path = (
            "cisco secure client" in normalized_root
            and "zero trust access" in normalized_root
            and "enrollments" in normalized_root
            and ("cached config" in normalized_root or "cached configs" in normalized_root)
        )
        if not has_required_path:
            continue

        for filename in files:
            if filename.lower().endswith(".json") and not filename.startswith("._"):
                json_files.append(os.path.join(current_root, filename))

    return json_files


def find_zta_enrollment_json_files(root_dir):
    json_files = []
    for current_root, _, files in os.walk(root_dir):
        normalized_root = current_root.lower().replace("_", " ")
        if "__macosx" in current_root.lower():
            continue
        has_required_path = (
            "cisco secure client" in normalized_root
            and "zero trust access" in normalized_root
            and "enrollments" in normalized_root
            and "cached config" not in normalized_root
            and "cached configs" not in normalized_root
        )
        if not has_required_path:
            continue

        for filename in files:
            if filename.lower().endswith(".json") and not filename.startswith("._"):
                json_files.append(os.path.join(current_root, filename))

    return json_files


def find_zta_enrollment_choice_json_files(root_dir):
    json_files = []
    for current_root, _, files in os.walk(root_dir):
        normalized_root = current_root.lower().replace("_", " ")
        if "__macosx" in current_root.lower():
            continue
        has_required_path = (
            "cisco secure client" in normalized_root
            and "zero trust access" in normalized_root
            and "enrollment choices" in normalized_root
        )
        if not has_required_path:
            continue

        for filename in files:
            if filename.lower().endswith(".json") and not filename.startswith("._"):
                json_files.append(os.path.join(current_root, filename))

    return json_files


def find_cert_enrollment_choice_json_files(root_dir, known_org_ids=None):
    known_org_ids = set(
        str(org_id).strip()
        for org_id in (known_org_ids or [])
        if str(org_id).strip()
    )
    cert_pattern = re.compile(r"^(?P<org_id>\d+)_ZTA_Enroll_Cert\.json$", re.IGNORECASE)
    matching_files = []
    fallback_files = []

    for choice_path in find_zta_enrollment_choice_json_files(root_dir):
        file_name = os.path.basename(choice_path)
        cert_match = cert_pattern.match(file_name)
        if not cert_match:
            continue
        fallback_files.append(choice_path)
        if known_org_ids and cert_match.group("org_id") in known_org_ids:
            matching_files.append(choice_path)

    if matching_files:
        return sorted(matching_files)
    return sorted(fallback_files)


def render_json_files_for_report(json_paths, base_dir):
    rendered_sections = []

    for json_path in json_paths:
        relative_path = os.path.relpath(json_path, base_dir)
        try:
            with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
                payload = json.load(handle)
            pretty_json = json.dumps(payload, indent=2, sort_keys=True)
        except (json.JSONDecodeError, OSError) as exc:
            pretty_json = f"[!] Unable to read JSON file: {exc}"

        rendered_sections.append(
            f"[Enrollment Choice File] {relative_path}\n{pretty_json}"
        )

    return "\n\n".join(rendered_sections)


def extract_identifier_scoped_enrollment_attempts(root_dir, trigger_phrase):
    completion_phrase = "Notifying enrollment completion with result:"
    bracket_identifier_pattern = re.compile(r"\[[^\]]*,\s*(0x[0-9a-fA-F]+)\]")
    macos_identifier_pattern = re.compile(
        r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?\s+(0x[0-9a-fA-F]+)\b"
    )
    generic_identifier_pattern = re.compile(r"\b0x[0-9a-fA-F]+\b")
    timestamp_pattern = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?")

    def parse_enrollment_timestamp(line_text):
        text = str(line_text or "").strip()
        if not text:
            return None

        timestamp_match = re.match(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)",
            text,
        )
        if not timestamp_match:
            return None

        raw_timestamp = timestamp_match.group(1)
        for pattern in (
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(raw_timestamp, pattern)
            except ValueError:
                continue

        return None

    def classify_completion_status(status_text):
        normalized = str(status_text or "").strip().lower()
        if not normalized:
            return ""
        if "success" in normalized or normalized in {"ok", "passed"}:
            return "success"
        if "error" in normalized or "fail" in normalized:
            return "failure"
        return "success"

    def sanitize_trace_line(line_text):
        line = str(line_text)
        if "Initiated HTTP request method=" in line and " with headers " in line:
            prefix = line.split(" with headers ", 1)[0].rstrip()
            return f"{prefix} with headers [omitted]"

        if "Authorization=" in line or " Dpop=" in line:
            # Keep readable context while omitting huge token payloads.
            compact = re.sub(r"Authorization=[^\s]+", "Authorization=[omitted]", line)
            compact = re.sub(r"Dpop=[^\s]+", "Dpop=[omitted]", compact)
            compact = re.sub(r"x-request-id=[^\s]+", "x-request-id=[omitted]", compact)
            compact = re.sub(r"x-zta-enrollment-id=[^\s]+", "x-zta-enrollment-id=[omitted]", compact)
            line = compact

        return line

    def extract_identifier_from_line(line_text):
        bracket_match = bracket_identifier_pattern.search(line_text)
        if bracket_match:
            return bracket_match.group(1)

        macos_match = macos_identifier_pattern.search(line_text)
        if macos_match:
            candidate_identifier = macos_match.group(1)
            if candidate_identifier and candidate_identifier.lower() not in {"0x0", "0x00", "0x0000"}:
                return candidate_identifier

        identifiers = generic_identifier_pattern.findall(line_text)
        for identifier in identifiers:
            if identifier.lower() not in {"0x0", "0x00", "0x0000"}:
                return identifier
        if identifiers:
            return identifiers[0]
        return ""

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    trigger_events = []

    # Collect every trigger event so each enrollment attempt can be rendered.
    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    if trigger_phrase not in line:
                        continue
                    candidate_identifier = extract_identifier_from_line(line)
                    if not candidate_identifier:
                        continue
                    trigger_events.append({
                        "log_path": log_path,
                        "line_number": line_number,
                        "line_text": line,
                        "identifier": candidate_identifier,
                    })
        except OSError:
            continue

    attempts = []
    for event in trigger_events:
        selected_identifier = event["identifier"]
        start_log_path = event["log_path"]
        start_line_number = event["line_number"]

        trace_lines = []
        completion_status = ""
        enrollment_status = ""
        enrollment_stats_lines = []
        capture_enrollment_stats_block = False
        completion_seen = False
        stop_after_stats = False
        attempt_start_timestamp = parse_enrollment_timestamp(event["line_text"])
        completion_timestamp = None

        identifier_match_pattern = re.compile(rf"\b{re.escape(selected_identifier)}\b", re.IGNORECASE)

        relative_location = f"{os.path.relpath(start_log_path, root_dir)}:L{start_line_number}"
        trace_lines.append(f"{relative_location} {sanitize_trace_line(event['line_text'])}")

        try:
            with open(start_log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    if line_number <= start_line_number:
                        continue

                    line = raw_line.rstrip("\n")

                    if capture_enrollment_stats_block:
                        if timestamp_pattern.match(line):
                            if enrollment_stats_lines:
                                capture_enrollment_stats_block = False
                                stop_after_stats = True
                            # Ignore timestamped lines immediately before the
                            # stats header and continue scanning.
                        else:
                            cleaned_line = line.rstrip()
                            if cleaned_line:
                                enrollment_stats_lines.append(cleaned_line)
                                # Keep stats block in native log format (no
                                # synthetic file/line prefix).
                                trace_lines.append(sanitize_trace_line(cleaned_line))
                                overall_match = re.search(
                                    r"Overall result\s*:\s*([^\s]+)",
                                    cleaned_line,
                                    re.IGNORECASE,
                                )
                                if overall_match:
                                    enrollment_status = overall_match.group(1)
                            continue

                    if stop_after_stats:
                        break

                    if not identifier_match_pattern.search(line):
                        continue

                    relative_location = f"{os.path.relpath(start_log_path, root_dir)}:L{line_number}"
                    trace_lines.append(f"{relative_location} {sanitize_trace_line(line)}")

                    if completion_phrase in line:
                        status_match = re.search(
                            r"Notifying enrollment completion with result:\s*([^\s]+)",
                            line,
                            re.IGNORECASE,
                        )
                        completion_status = (
                            status_match.group(1) if status_match else "Unknown"
                        )
                        completion_timestamp = parse_enrollment_timestamp(line)
                        completion_seen = True

                    if (
                        completion_seen
                        and "actionNotifyCompletion()" in line
                        and completion_phrase not in line
                    ):
                        capture_enrollment_stats_block = True
        except OSError:
            continue

        if not enrollment_status and completion_status:
            enrollment_status = completion_status

        if not enrollment_stats_lines and completion_status:
            completion_outcome = classify_completion_status(completion_status)
            elapsed_seconds = None
            if attempt_start_timestamp is not None and completion_timestamp is not None:
                try:
                    elapsed_seconds = max(
                        0.0,
                        (completion_timestamp - attempt_start_timestamp).total_seconds(),
                    )
                except Exception:
                    elapsed_seconds = None

            elapsed_text = f" ({elapsed_seconds:.3f} sec)" if elapsed_seconds is not None else ""
            auth_type = "certificate" if "certificate authentication" in trigger_phrase.lower() else "saml"
            enrollment_stats_lines = [
                "Enrollment Stats",
                "================",
                f"Authentication type           : {auth_type}",
                f"Bootstrap                     : {completion_outcome}{elapsed_text}",
                "----------------",
                f"Overall result                : {completion_outcome}{elapsed_text}",
            ]
            trace_lines.extend(enrollment_stats_lines)

        attempts.append({
            "identifier": selected_identifier,
            "trace_lines": trace_lines,
            "completion_status": completion_status,
            "enrollment_status": enrollment_status,
            "enrollment_stats_lines": enrollment_stats_lines,
        })

    return attempts


def extract_cert_auto_enrollment_trace_macos_5114(root_dir):
    trigger_phrase = (
        "Current enrollment choice has certificate authentication, "
        "initiating automatic enrollment"
    )
    saml_trigger_phrase = "InitiateEnrollment() Initiating Enrollment(SAML)"
    event_start_phrase = "SSEZtnaEnroller.cpp:186 eventStart() Processing start event"
    completion_pattern = re.compile(
        r"actionNotifyCompletion\(\)\s+Notifying enrollment completion with result:\s*([^\s]+)",
        re.IGNORECASE,
    )
    timestamp_line_pattern = re.compile(
        r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?"
    )

    def parse_enrollment_timestamp(line_text):
        text = str(line_text or "").strip()
        if not text:
            return None

        timestamp_match = re.match(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)",
            text,
        )
        if not timestamp_match:
            return None

        raw_timestamp = timestamp_match.group(1)
        for pattern in (
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(raw_timestamp, pattern)
            except ValueError:
                continue

        return None

    def classify_completion_status(status_text):
        normalized = str(status_text or "").strip().lower()
        if not normalized:
            return ""
        if "success" in normalized or normalized in {"ok", "passed"}:
            return "success"
        if "error" in normalized or "fail" in normalized:
            return "failure"
        return normalized

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    attempts = []

    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                lines = [line.rstrip("\n") for line in handle]
        except OSError:
            continue

        start_indexes = set()

        # Preferred anchor: cert trigger phrase followed by eventStart.
        for trigger_index, line in enumerate(lines):
            if trigger_phrase not in line:
                continue
            for next_index in range(trigger_index + 1, len(lines)):
                if event_start_phrase in lines[next_index]:
                    start_indexes.add(next_index)
                    break

        # Fallback and coverage anchor: capture every eventStart attempt. This
        # includes early failures (for example InitializationError) where the
        # trigger phrase may not be emitted in the same attempt.
        for idx, line in enumerate(lines):
            if event_start_phrase in line:
                start_indexes.add(idx)

        # Additional coverage anchor: capture completion-led attempts where the
        # log only records actionNotifyCompletion + Enrollment Stats without a
        # nearby eventStart marker.
        for idx, line in enumerate(lines):
            if not completion_pattern.search(line):
                continue

            has_nearby_event_start = any(
                event_start_phrase in probe_line
                for probe_line in lines[max(0, idx - 200):idx + 1]
            )
            if not has_nearby_event_start:
                start_indexes.add(idx)

        for start_index in sorted(start_indexes):
            has_cert_context = any(
                trigger_phrase in probe_line
                for probe_line in lines[max(0, start_index - 300):start_index + 1]
            )
            has_saml_context = any(
                saml_trigger_phrase in probe_line
                for probe_line in lines[max(0, start_index - 300):start_index + 1]
            )

            trace_lines = []
            completion_status = ""
            enrollment_status = ""
            enrollment_stats_lines = []
            authentication_type = ""
            attempt_start_timestamp = parse_enrollment_timestamp(lines[start_index])
            completion_timestamp = None
            capture_enrollment_stats_block = False
            stats_block_started = False

            stats_line_tokens = (
                "Enrollment Stats",
                "Authentication type",
                "Bootstrap",
                "DeviceRegistration",
                "DHARegistration",
                "DHAEnrollment",
                "DHAEnrollmentNotification",
                "ACMEEnrollment",
                "PersistEnrollment",
                "Overall result",
            )

            for idx in range(start_index, len(lines)):
                current_line = lines[idx]
                if capture_enrollment_stats_block:
                    if timestamp_line_pattern.match(current_line):
                        if stats_block_started:
                            break
                        continue

                    cleaned_line = current_line.rstrip()
                    if not cleaned_line:
                        if stats_block_started:
                            continue
                        continue

                    should_capture = (
                        cleaned_line == "================"
                        or cleaned_line == "----------------"
                        or any(token in cleaned_line for token in stats_line_tokens)
                    )

                    if should_capture or stats_block_started:
                        stats_block_started = True
                        enrollment_stats_lines.append(cleaned_line)
                        trace_lines.append(cleaned_line)

                        overall_match = re.search(
                            r"Overall result\s*:\s*([^\s]+)",
                            cleaned_line,
                            re.IGNORECASE,
                        )
                        if overall_match:
                            enrollment_status = overall_match.group(1).strip()

                        auth_match = re.search(
                            r"Authentication\s+type\s*:\s*([^\s]+)",
                            cleaned_line,
                            re.IGNORECASE,
                        )
                        if auth_match:
                            authentication_type = auth_match.group(1).strip()
                        continue

                if "SSEZtnaEnroller" not in current_line:
                    continue

                relative_location = f"{os.path.relpath(log_path, root_dir)}:L{idx + 1}"
                trace_lines.append(f"{relative_location} {current_line}")

                completion_match = completion_pattern.search(current_line)
                if completion_match:
                    completion_status = completion_match.group(1).strip()
                    completion_timestamp = parse_enrollment_timestamp(current_line)
                    capture_enrollment_stats_block = True

            if not trace_lines:
                continue

            normalized_auth_type = authentication_type.strip().lower()
            if normalized_auth_type and normalized_auth_type not in {"certificate", "cert"}:
                # Cert enrollment mode should not include SAML attempts.
                continue
            if has_saml_context and not has_cert_context:
                # Explicit SAML initiation marker takes precedence when cert
                # context is not present.
                continue
            if not normalized_auth_type and not has_cert_context:
                # If auth type is missing, require nearby certificate trigger context
                # to avoid mixing in non-cert enrollment attempts.
                continue

            if completion_status:
                if not enrollment_status:
                    enrollment_status = completion_status
                completion_outcome = classify_completion_status(completion_status)
                elapsed_seconds = None
                if attempt_start_timestamp is not None and completion_timestamp is not None:
                    try:
                        elapsed_seconds = max(
                            0.0,
                            (completion_timestamp - attempt_start_timestamp).total_seconds(),
                        )
                    except Exception:
                        elapsed_seconds = None

                if not enrollment_stats_lines:
                    elapsed_text = f" ({elapsed_seconds:.3f} sec)" if elapsed_seconds is not None else ""
                    enrollment_stats_lines = [
                        "Enrollment Stats",
                        "================",
                        "Authentication type           : certificate",
                        f"Bootstrap                     : {completion_outcome}{elapsed_text}",
                        "----------------",
                        f"Overall result                : {completion_outcome}{elapsed_text}",
                    ]
                    trace_lines.extend(enrollment_stats_lines)

            attempts.append({
                "identifier": "",
                "trace_lines": trace_lines,
                "completion_status": completion_status,
                "enrollment_status": enrollment_status,
                "enrollment_stats_lines": enrollment_stats_lines,
            })

    return attempts


def extract_cert_auto_enrollment_trace(root_dir):
    operating_system = extract_operating_system_from_bundle(root_dir)
    component_versions = extract_component_versions_from_bundle(root_dir)
    zta_version = str(component_versions.get("zta_version") or "").strip()

    # macOS 5.1.14 cert bundles use SSEZtnaEnroller eventStart/actionNotifyCompletion
    # sequence; capture this flow first and fall back to generic identifier logic.
    if "mac" in operating_system.lower() and zta_version.startswith("5.1.14"):
        mac_attempts = extract_cert_auto_enrollment_trace_macos_5114(root_dir)
        if mac_attempts:
            latest = mac_attempts[-1]
            return {
                **latest,
                "attempts": mac_attempts,
            }

    trigger_phrase = (
        "Current enrollment choice has certificate authentication, "
        "initiating automatic enrollment"
    )
    attempts = extract_identifier_scoped_enrollment_attempts(root_dir, trigger_phrase)
    if not attempts:
        return {
            "identifier": "",
            "trace_lines": [],
            "completion_status": "",
            "enrollment_status": "",
            "enrollment_stats_lines": [],
            "attempts": [],
        }

    latest = attempts[-1]
    return {
        **latest,
        "attempts": attempts,
    }


def extract_saml_auto_enrollment_trace(root_dir):
    trigger_phrase = "Handling InitiateEnrollment from client"
    attempts = extract_identifier_scoped_enrollment_attempts(root_dir, trigger_phrase)
    if not attempts:
        return {
            "identifier": "",
            "trace_lines": [],
            "completion_status": "",
            "enrollment_status": "",
            "enrollment_stats_lines": [],
            "attempts": [],
        }

    latest = attempts[-1]
    return {
        **latest,
        "attempts": attempts,
    }


def detect_auth_method_from_enrollment_choice_files(root_dir, known_org_ids=None):
    known_org_ids = set(str(org_id).strip() for org_id in (known_org_ids or []) if str(org_id).strip())
    choice_files = find_zta_enrollment_choice_json_files(root_dir)
    if not choice_files:
        return None

    cert_pattern = re.compile(r"^(?P<org_id>\d+)_ZTA_Enroll_Cert\.json$", re.IGNORECASE)
    saml_pattern = re.compile(r"^(?P<org_id>\d+)_ZTA_Enroll_SAML\.json$", re.IGNORECASE)

    cert_match_for_known_org = False
    saml_match_for_known_org = False
    cert_match_any = False
    saml_match_any = False

    for choice_path in choice_files:
        file_name = os.path.basename(choice_path)

        cert_match = cert_pattern.match(file_name)
        if cert_match:
            cert_match_any = True
            if not known_org_ids or cert_match.group("org_id") in known_org_ids:
                cert_match_for_known_org = True

        saml_match = saml_pattern.match(file_name)
        if saml_match:
            saml_match_any = True
            if not known_org_ids or saml_match.group("org_id") in known_org_ids:
                saml_match_for_known_org = True

    if cert_match_for_known_org or cert_match_any:
        return "Cert-based Auth"
    if saml_match_for_known_org or saml_match_any:
        return "SAML-based Auth"

    return None


def extract_org_ids_from_enrollments(root_dir):
    org_ids = []
    user_ids = []
    numeric_user_ids = []
    enrollment_methods = []
    enrollment_times = []
    enrollment_urls = []
    warnings = []
    email_pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    bundle_timezone, bundle_timezone_name = resolve_bundle_timezone(root_dir)
    saw_certificate_indicators = False

    def normalize_enrollment_method(raw_value):
        if raw_value is None:
            return ""
        value = str(raw_value).strip().lower()
        if not value or value in {"none", "n/a", "na", "null", "unknown"}:
            return ""
        if "saml" in value:
            return "SAML-based Auth"
        if "cert" in value or "certificate" in value:
            return "Cert-based Auth"
        return str(raw_value).strip()

    def normalize_enrollment_time(raw_value):
        text = str(raw_value).strip()
        if not text:
            return ""
        try:
            timestamp = int(text)
        except ValueError:
            return text

        try:
            return datetime.fromtimestamp(timestamp, tz=bundle_timezone).strftime(
                f"%Y-%m-%d %H:%M:%S {bundle_timezone_name}"
            )
        except (OverflowError, OSError, ValueError):
            return text

    for json_path in find_zta_enrollment_json_files(root_dir):
        relative_path = os.path.relpath(json_path, root_dir)
        try:
            with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
                payload = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            warnings.append(f"{relative_path} -> {exc}")
            continue

        org_id = get_case_insensitive_value(payload, "org_id")
        if org_id is None:
            config_sync_url = str(get_case_insensitive_value(payload, "config_sync_url", "")).strip()
            match = re.search(r"proxy-(\d+)\.zpc\.sse\.cisco\.com", config_sync_url, re.IGNORECASE)
            if match:
                org_id = match.group(1)

        if org_id is not None:
            normalized_org_id = str(org_id).strip()
            if normalized_org_id:
                org_ids.append(normalized_org_id)

        user_id = get_case_insensitive_value(payload, "user_id")
        if user_id is not None:
            normalized_user_id = str(user_id).strip()
            if normalized_user_id:
                numeric_user_ids.append(normalized_user_id)

        label = str(get_case_insensitive_value(payload, "label", "")).strip()
        if label:
            label_email_matches = email_pattern.findall(label)
            if label_email_matches:
                user_ids.extend(label_email_matches)
            else:
                label_match = re.search(r"by user\s+(.+)$", label, re.IGNORECASE)
                if label_match:
                    normalized_label_user = label_match.group(1).strip()
                    if normalized_label_user:
                        user_ids.append(normalized_label_user)

        certificate_indicators = [
            str(get_case_insensitive_value(payload, "client_cert_alias", "")).strip(),
            str(get_case_insensitive_value(payload, "client_cert_file", "")).strip(),
            str(get_case_insensitive_value(payload, "certificate_state", "")).strip(),
            str(get_case_insensitive_value(payload, "certificate_renewal_status", "")).strip(),
        ]
        if any(value for value in certificate_indicators):
            saw_certificate_indicators = True

        enrollment_time = get_case_insensitive_value(payload, "enrollment_time")
        if enrollment_time is not None:
            normalized_enrollment_time = normalize_enrollment_time(enrollment_time)
            if normalized_enrollment_time:
                enrollment_times.append(normalized_enrollment_time)

        for key, value in payload.items():
            normalized_key = str(key).strip().lower()
            if "url" not in normalized_key and normalized_key != "dha_base_url":
                continue

            normalized_value = str(value).strip()
            if normalized_value:
                enrollment_urls.append(normalized_value)

    # Fallback for bundles where enrollment JSON lacks org_id fields:
    # parse ORG ID from enrollment-choice file names like
    # <org_id>_ZTA_Enroll_Cert.json or <org_id>_ZTA_Enroll_SAML.json.
    if not org_ids:
        org_filename_pattern = re.compile(
            r"^(?P<org_id>\d+)_ZTA_Enroll_(?:Cert|SAML)\.json$",
            re.IGNORECASE,
        )
        for choice_path in find_zta_enrollment_choice_json_files(root_dir):
            file_name = os.path.basename(choice_path)
            match = org_filename_pattern.match(file_name)
            if not match:
                continue
            fallback_org_id = str(match.group("org_id") or "").strip()
            if fallback_org_id:
                org_ids.append(fallback_org_id)

    filename_based_auth_method = detect_auth_method_from_enrollment_choice_files(
        root_dir,
        known_org_ids=org_ids,
    )
    if filename_based_auth_method:
        effective_enrollment_method = filename_based_auth_method
    elif org_ids or numeric_user_ids or user_ids:
        effective_enrollment_method = "SAML-based Auth"
    else:
        effective_enrollment_method = ""

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    url_pattern = re.compile(r"https?://[^\s\"']+")
    key_value_url_pattern = re.compile(
        r"(?:bootstrapUrl|certRenewalUrl|configSyncUrl|config_sync_url|acme_dir_url|dha_base_url)=(?:\"?)([^\s\"]+)",
        re.IGNORECASE,
    )
    auth_type_pattern = re.compile(r"authType=([^\s,]+)", re.IGNORECASE)
    enrollment_url_keywords = (
        "enroll",
        "bootstrapurl",
        "renewalurl",
        "config_sync",
        "zta-config",
        "acme",
        "sync url",
    )
    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    lowered_line = line.lower()

                    if "username=" in lowered_line or "user " in lowered_line:
                        for email_match in email_pattern.findall(line):
                            user_ids.append(email_match)

                    if not any(keyword in lowered_line for keyword in enrollment_url_keywords):
                        continue

                    for key_value_match in key_value_url_pattern.findall(line):
                        normalized_url = str(key_value_match).replace('\\/', '/').strip('.,);]"')
                        if normalized_url and normalized_url != "N/A":
                            enrollment_urls.append(normalized_url)

                    for url_match in url_pattern.findall(line):
                        normalized_url = url_match.replace('\\/', '/').strip('.,);]')
                        if not normalized_url or normalized_url == "N/A":
                            continue
                        if (
                            "enroll" in normalized_url.lower()
                            or "zta-config" in normalized_url.lower()
                            or "acme" in normalized_url.lower()
                        ):
                            enrollment_urls.append(normalized_url)
        except OSError:
            continue

    if effective_enrollment_method:
        enrollment_methods = [effective_enrollment_method]
    elif saw_certificate_indicators:
        # Keep legacy fallback only when no enrollment identifiers were found.
        enrollment_methods = ["Cert-based Auth"]

    return {
        "org_ids": sorted(set(org_ids)),
        "user_ids": sorted(set(user_ids)),
        "numeric_user_ids": sorted(set(numeric_user_ids)),
        "enrollment_methods": sorted(set(enrollment_methods)),
        "enrollment_times": sorted(set(enrollment_times)),
        "enrollment_urls": sorted(set(enrollment_urls)),
        "warnings": warnings,
    }


def find_bundle_summary_file(root_dir):
    for current_root, _, files in os.walk(root_dir):
        if "__macosx" in current_root.lower():
            continue
        for filename in files:
            if filename.lower() == "summary.txt" and not filename.startswith("._"):
                return os.path.join(current_root, filename)
    return None


WINDOWS_TIMEZONE_TO_IANA = {
    **WINDOWS_TZLOCAL_MAP,
    "AUS Eastern Standard Time": "Australia/Sydney",
    "AUS Central Standard Time": "Australia/Darwin",
    "Central Europe Standard Time": "Europe/Budapest",
    "Central Europe Daylight Time": "Europe/Budapest",
    "Central European Standard Time": "Europe/Berlin",
    "Central European Daylight Time": "Europe/Berlin",
    "W. Europe Standard Time": "Europe/Berlin",
    "Romance Standard Time": "Europe/Paris",
    "CEST": "Europe/Berlin",
    "CEDT": "Europe/Berlin",
    "CET": "Europe/Berlin",
    "E. Australia Standard Time": "Australia/Brisbane",
    "FLE Standard Time": "Europe/Helsinki",
    "FLE Daylight Time": "Europe/Helsinki",
    "Tasmania Standard Time": "Australia/Hobart",
    "W. Australia Standard Time": "Australia/Perth",
    "UTC": "UTC",
}

WINDOWS_TIMEZONE_DISPLAY_NAMES = {
    "AUS Eastern Standard Time": "Australia Eastern Standard Time",
    "AUS Central Standard Time": "Australia Central Standard Time",
    "Central Europe Standard Time": "Central Europe Standard Time",
    "Central Europe Daylight Time": "Central Europe Daylight Time",
    "Central European Standard Time": "Central European Standard Time",
    "Central European Daylight Time": "Central European Daylight Time",
    "W. Europe Standard Time": "Western Europe Standard Time",
    "Romance Standard Time": "Romance Standard Time",
    "CEST": "Central European Summer Time",
    "CEDT": "Central European Daylight Time",
    "CET": "Central European Time",
    "E. Australia Standard Time": "Australia Standard Time",
    "FLE Standard Time": "Finland Local Time",
    "FLE Daylight Time": "Finland Local Time",
    "Tasmania Standard Time": "Tasmania Standard Time",
    "W. Australia Standard Time": "Western Australia Standard Time",
}


def extract_bundle_timezone_name(root_dir):
    summary_path = find_bundle_summary_file(root_dir)
    if not summary_path:
        return ""

    try:
        with open(summary_path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                raw_line = str(line or "").strip()
                if not raw_line.lower().startswith("time:"):
                    continue

                payload = re.sub(r"^\s*Time:\s*", "", raw_line, flags=re.IGNORECASE).strip()
                year_match = re.search(r"\b\d{4}\b\s+(.+?)\s*$", payload)
                if year_match:
                    return year_match.group(1).strip()

                # Fallback: when formatting is non-standard, use trailing token as timezone.
                pieces = payload.split()
                if pieces:
                    return pieces[-1].strip()
    except OSError:
        return ""

    return ""


def resolve_bundle_timezone(root_dir):
    timezone_name = extract_bundle_timezone_name(root_dir)
    if not timezone_name:
        return timezone.utc, "UTC"

    normalized_timezone_name = re.sub(r"\s+", " ", str(timezone_name or "").strip())
    candidate_names = [normalized_timezone_name]

    parenthetical_match = re.search(r"\(([^()]+)\)", normalized_timezone_name)
    if parenthetical_match:
        candidate_names.append(parenthetical_match.group(1).strip())
        candidate_names.append(re.sub(r"\s*\([^()]+\)\s*", "", normalized_timezone_name).strip())

    for candidate_name in candidate_names:
        if not candidate_name:
            continue

        iana_name = WINDOWS_TIMEZONE_TO_IANA.get(candidate_name, candidate_name)
        display_name = WINDOWS_TIMEZONE_DISPLAY_NAMES.get(candidate_name, candidate_name)
        if iana_name == candidate_name and candidate_name.endswith("Daylight Time"):
            standard_timezone_name = candidate_name.replace("Daylight Time", "Standard Time")
            iana_name = WINDOWS_TIMEZONE_TO_IANA.get(standard_timezone_name, iana_name)
            display_name = WINDOWS_TIMEZONE_DISPLAY_NAMES.get(standard_timezone_name, display_name)

        try:
            return ZoneInfo(iana_name), display_name
        except Exception:
            pass

        offset_match = re.fullmatch(
            r"(?:UTC|GMT)\s*([+-])\s*(\d{1,2})(?::?(\d{2}))?",
            candidate_name,
            flags=re.IGNORECASE,
        )
        if offset_match:
            sign = 1 if offset_match.group(1) == "+" else -1
            hours = int(offset_match.group(2))
            minutes = int(offset_match.group(3) or "0")
            offset = sign * timedelta(hours=hours, minutes=minutes)
            return timezone(offset), f"UTC{offset_match.group(1)}{hours:02d}:{minutes:02d}"

    return timezone.utc, "UTC"


def extract_operating_system_from_bundle(root_dir):
    summary_path = find_bundle_summary_file(root_dir)
    if not summary_path:
        return "Unknown"

    try:
        with open(summary_path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                match = re.match(r"\s*OS:\s*(.+?)\s*$", line)
                if match:
                    return match.group(1).strip()
    except OSError:
        return "Unknown"

    return "Unknown"


def find_module_log_text_files(root_dir, module_folder_name):
    log_files = []
    normalized_module_name = str(module_folder_name).lower()

    for current_root, _, files in os.walk(root_dir):
        normalized_root = current_root.lower().replace("_", " ")
        if "__macosx" in current_root.lower():
            continue
        if "cisco secure client" not in normalized_root:
            continue
        if normalized_module_name not in normalized_root:
            continue
        if "logs" not in normalized_root:
            continue

        for filename in files:
            lowered_name = filename.lower()
            if filename.startswith("._"):
                continue
            if lowered_name.endswith(".txt") or lowered_name.endswith(".log"):
                log_files.append(os.path.join(current_root, filename))

    return sorted(log_files)


def find_duo_desktop_logs_root_dirs(root_dir):
    def is_duo_user_folder_name(folder_name):
        candidate = str(folder_name or "").strip()
        if not candidate or candidate.startswith("."):
            return False
        # Typical Duo user folders are user-id like names, often containing dots.
        if "." not in candidate:
            return False
        if not re.match(r"^[A-Za-z0-9._-]+$", candidate):
            return False

        lowered = candidate.lower()
        blocked_tokens = {
            "log",
            "logs",
            "service",
            "services",
            "support",
            "cache",
            "config",
            "system",
            "temp",
            "tmp",
        }
        if any(token in lowered for token in blocked_tokens):
            return False
        return True

    root_dirs = []
    for current_root, dirs, _ in os.walk(root_dir):
        normalized_root = current_root.lower().replace("_", " ")
        if "__macosx" in current_root.lower():
            continue
        has_duo_context = (
            "duo desktop logs" in normalized_root
            or "duo desktop support" in normalized_root
            or "duo desktop" in normalized_root
            or "duodesktop" in normalized_root
        )
        if not has_duo_context:
            continue

        has_user_folder = any(is_duo_user_folder_name(dir_name) for dir_name in dirs)
        if "duo desktop logs" in normalized_root or has_user_folder:
            root_dirs.append(current_root)

    # Prefer shallow-most paths first so immediate user folder discovery is stable.
    root_dirs = sorted(set(root_dirs), key=lambda path: path.count(os.sep))
    return root_dirs


def get_duo_desktop_user_folders(root_dir):
    def is_duo_user_folder_name(folder_name):
        candidate = str(folder_name or "").strip()
        if not candidate or candidate.startswith("."):
            return False
        if "." not in candidate:
            return False
        if not re.match(r"^[A-Za-z0-9._-]+$", candidate):
            return False

        lowered = candidate.lower()
        blocked_tokens = {
            "log",
            "logs",
            "service",
            "services",
            "support",
            "cache",
            "config",
            "system",
            "temp",
            "tmp",
        }
        if any(token in lowered for token in blocked_tokens):
            return False
        return True

    user_folder_names = set()

    for logs_root in find_duo_desktop_logs_root_dirs(root_dir):
        try:
            with os.scandir(logs_root) as entries:
                for entry in entries:
                    if not entry.is_dir():
                        continue
                    if entry.name.startswith("."):
                        continue
                    if is_duo_user_folder_name(entry.name):
                        user_folder_names.add(entry.name)
        except OSError:
            continue

    return sorted(user_folder_names)


def is_duo_desktop_detailed_logging_enabled(root_dir):
    return bool(get_duo_desktop_user_folders(root_dir))


def collect_duo_desktop_failed_error_lines(root_dir):
    keyword_pattern = re.compile(r"\b(failed|error)\b", re.IGNORECASE)
    user_folders = get_duo_desktop_user_folders(root_dir)
    if not user_folders:
        return {
            "user_folders": [],
            "matches": [],
        }

    logs_roots = find_duo_desktop_logs_root_dirs(root_dir)
    selected_user_dirs = []
    seen_user_dirs = set()

    for logs_root in logs_roots:
        for user_folder in user_folders:
            candidate_dir = os.path.join(logs_root, user_folder)
            if not os.path.isdir(candidate_dir):
                continue
            if candidate_dir in seen_user_dirs:
                continue
            seen_user_dirs.add(candidate_dir)
            selected_user_dirs.append((user_folder, candidate_dir))

    matches = []
    for user_folder, user_dir in selected_user_dirs:
        for current_root, _, files in os.walk(user_dir):
            for filename in files:
                if filename.startswith("._") or filename.startswith("."):
                    continue
                file_path = os.path.join(current_root, filename)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                        for line_number, raw_line in enumerate(handle, start=1):
                            line = raw_line.rstrip("\n")
                            if keyword_pattern.search(line):
                                matches.append(
                                    {
                                        "user_folder": user_folder,
                                        "path": file_path,
                                        "line_number": line_number,
                                        "line": line,
                                    }
                                )
                except OSError:
                    continue

    matches.sort(key=lambda item: (item["user_folder"].lower(), item["path"], item["line_number"]))
    return {
        "user_folders": user_folders,
        "matches": matches,
    }


def find_duo_desktop_user_log_files(root_dir):
    user_folders = get_duo_desktop_user_folders(root_dir)
    if not user_folders:
        return []

    logs_roots = find_duo_desktop_logs_root_dirs(root_dir)
    selected_user_dirs = []
    seen_user_dirs = set()

    for logs_root in logs_roots:
        for user_folder in user_folders:
            candidate_dir = os.path.join(logs_root, user_folder)
            if not os.path.isdir(candidate_dir):
                continue
            if candidate_dir in seen_user_dirs:
                continue
            seen_user_dirs.add(candidate_dir)
            selected_user_dirs.append(candidate_dir)

    log_files = []
    for user_dir in selected_user_dirs:
        for current_root, _, files in os.walk(user_dir):
            for filename in files:
                lowered_name = filename.lower()
                if filename.startswith("._") or filename.startswith("."):
                    continue
                if lowered_name.endswith(".log") or lowered_name.endswith(".txt"):
                    log_files.append(os.path.join(current_root, filename))

    return sorted(set(log_files))


def find_duo_desktop_service_log_files(root_dir):
    service_log_files = []

    for current_root, _, files in os.walk(root_dir):
        normalized_root = current_root.lower().replace("_", " ")
        if "__macosx" in current_root.lower():
            continue
        if "duo desktop service logs" not in normalized_root:
            continue

        for filename in files:
            lowered_name = filename.lower()
            if filename.startswith("._") or filename.startswith("."):
                continue
            if lowered_name.endswith(".log") or lowered_name.endswith(".txt"):
                service_log_files.append(os.path.join(current_root, filename))

    return sorted(set(service_log_files))


def categorize_duo_service_log_files(service_log_files):
    categorized = {
        "Crypto Service logs": [],
        "TrustedPeerMessageBroker Logs": [],
        "Duo Desktop Updater logs": [],
    }

    for log_path in service_log_files:
        lowered_path = log_path.lower().replace("_", " ")
        lowered_name = os.path.basename(log_path).lower().replace("_", " ")
        joined = f"{lowered_path} {lowered_name}"

        if "trustedpeermessagebroker" in joined or "trusted peer message broker" in joined:
            categorized["TrustedPeerMessageBroker Logs"].append(log_path)
            continue
        if "crypto service" in joined or "cryptoservice" in joined:
            categorized["Crypto Service logs"].append(log_path)
            continue
        if "updater" in joined:
            categorized["Duo Desktop Updater logs"].append(log_path)

    for key in categorized:
        categorized[key] = sorted(set(categorized[key]))

    return categorized


def collect_failed_error_lines_from_log_files(log_paths):
    keyword_pattern = re.compile(r"\b(failed|error|exception)\b", re.IGNORECASE)
    matches = []

    for log_path in log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    if keyword_pattern.search(line):
                        matches.append(
                            {
                                "path": log_path,
                                "line_number": line_number,
                                "line": line,
                            }
                        )
        except OSError:
            continue

    matches.sort(key=lambda item: (item["path"], item["line_number"]))
    return matches


def collect_matching_lines_from_log_files(log_paths, filter_text):
    needle = str(filter_text or "").strip()
    if not needle:
        return []

    search_pattern = re.compile(re.escape(needle), re.IGNORECASE)
    matches = []

    for log_path in log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    if search_pattern.search(line):
                        matches.append(
                            {
                                "path": log_path,
                                "line_number": line_number,
                                "line": line,
                            }
                        )
        except OSError:
            continue

    matches.sort(key=lambda item: (item["path"], item["line_number"]))
    return matches


def summarize_duo_filtered_lines_with_timeframes(matches, bundle_timezone, bundle_timezone_name, max_items=80):
    iso_prefix_pattern = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?\s*")
    slash_prefix_pattern = re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\s*")
    iso_timestamp_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)")
    slash_timestamp_pattern = re.compile(r"(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})")
    duration_pattern = re.compile(r"\b\d+ms\b", re.IGNORECASE)
    attempt_pattern = re.compile(r"\battempt\s+\d+\b", re.IGNORECASE)
    hex_hresult_pattern = re.compile(r"0x[0-9a-fA-F]+")

    grouped = {}

    def to_display_pattern(template_line):
        cleaned = str(template_line or "").strip().lstrip("|")
        if not cleaned:
            return template_line

        parts = [segment.strip() for segment in cleaned.split("|")]
        if len(parts) >= 3:
            # Keep the human-meaningful message while removing noisy logger metadata.
            message = " | ".join(parts[2:]).strip()
            return message or template_line

        return template_line

    for match in matches:
        raw_line = str(match.get("line", "")).strip()
        if not raw_line:
            continue

        normalized = iso_prefix_pattern.sub("", raw_line)
        normalized = slash_prefix_pattern.sub("", normalized)
        normalized = normalized.strip(" -:\t")
        sample_line = normalized or raw_line

        template_line = duration_pattern.sub("{duration}", sample_line)
        template_line = attempt_pattern.sub("attempt {n}", template_line)
        template_line = hex_hresult_pattern.sub("{hex}", template_line)
        template_line = re.sub(r"\s{2,}", " ", template_line).strip()

        key = template_line.lower()

        if key not in grouped:
            grouped[key] = {
                "sample": template_line,
                "pattern": to_display_pattern(template_line),
                "count": 0,
                "start_dt": None,
                "end_dt": None,
                "raw_lines": [],
                "seen_raw_lines": set(),
            }

        grouped[key]["count"] += 1
        if raw_line not in grouped[key]["seen_raw_lines"]:
            grouped[key]["seen_raw_lines"].add(raw_line)
            grouped[key]["raw_lines"].append(raw_line)

        for timestamp_match in iso_timestamp_pattern.finditer(raw_line):
            parsed = parse_log_timestamp(timestamp_match.group(1))
            if parsed is None:
                continue
            if grouped[key]["start_dt"] is None or parsed < grouped[key]["start_dt"]:
                grouped[key]["start_dt"] = parsed
            if grouped[key]["end_dt"] is None or parsed > grouped[key]["end_dt"]:
                grouped[key]["end_dt"] = parsed

        for timestamp_match in slash_timestamp_pattern.finditer(raw_line):
            parsed = parse_log_timestamp(timestamp_match.group(1))
            if parsed is None:
                continue
            if grouped[key]["start_dt"] is None or parsed < grouped[key]["start_dt"]:
                grouped[key]["start_dt"] = parsed
            if grouped[key]["end_dt"] is None or parsed > grouped[key]["end_dt"]:
                grouped[key]["end_dt"] = parsed

    condensed = sorted(
        grouped.values(),
        key=lambda item: (-item["count"], item["sample"].lower()),
    )

    results = []
    for item in condensed[:max_items]:
        start_text = format_bundle_local_timestamp(item["start_dt"], bundle_timezone, bundle_timezone_name)
        end_text = format_bundle_local_timestamp(item["end_dt"], bundle_timezone, bundle_timezone_name)

        start_core = split_timestamp_and_timezone(start_text)["timestamp"] if start_text else None
        end_core = split_timestamp_and_timezone(end_text)["timestamp"] if end_text else None

        if start_core and end_core:
            if start_core == end_core:
                timeframe_text = start_core
            else:
                timeframe_text = f"{start_core} -> {end_core}"
        else:
            timeframe_text = "Not found"

        safe_pattern = re.sub(r"[^A-Za-z0-9._-]+", "_", str(item["pattern"] or "pattern")).strip("_")
        if not safe_pattern:
            safe_pattern = "pattern"

        results.append(
            {
                "pattern": item["pattern"],
                "hits": item["count"],
                "first_seen": start_core or "Not found",
                "last_seen": end_core or "Not found",
                "timeframe": timeframe_text,
                "download_text": "\n".join(item["raw_lines"]),
                "download_filename": f"duo_posture_{safe_pattern}.log",
            }
        )

    return results


def analyze_duo_health_report_status(log_paths, bundle_timezone, bundle_timezone_name):
    send_pattern = re.compile(r"sending health report data to\s+(\S+)", re.IGNORECASE)
    ok_pattern = re.compile(r"Got response:\s*200\s*'OK'", re.IGNORECASE)
    reporter_pattern = re.compile(r"DeviceHealthReporter", re.IGNORECASE)
    error_pattern = re.compile(r"\b(failed|error|exception|timeout|unable)\b", re.IGNORECASE)
    timestamp_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)")

    pending_sends = []
    sent_count = 0
    ok_count = 0
    health_error_matches = []
    transaction_lines = []
    seen_transaction_lines = set()
    log_window = {
        "start_dt": None,
        "end_dt": None,
    }

    for log_path in log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")

                    for timestamp_match in timestamp_pattern.finditer(line):
                        update_log_window_bounds(log_window, timestamp_match.group(1))

                    send_match = send_pattern.search(line)
                    if send_match:
                        sent_count += 1
                        if line not in seen_transaction_lines:
                            seen_transaction_lines.add(line)
                            transaction_lines.append(line)
                        pending_sends.append(
                            {
                                "path": log_path,
                                "line_number": line_number,
                                "line": line,
                            }
                        )
                        continue

                    if ok_pattern.search(line):
                        ok_count += 1
                        if line not in seen_transaction_lines:
                            seen_transaction_lines.add(line)
                            transaction_lines.append(line)
                        if pending_sends:
                            pending_sends.pop(0)
                        continue

                    if reporter_pattern.search(line) and error_pattern.search(line):
                        health_error_matches.append(
                            {
                                "path": log_path,
                                "line_number": line_number,
                                "line": line,
                            }
                        )
        except OSError:
            continue

    return {
        "sent_count": sent_count,
        "ok_count": ok_count,
        "missing_count": max(0, len(pending_sends)),
        "missing_requests": pending_sends,
        "error_matches": health_error_matches,
        "transaction_lines": transaction_lines,
        "timeframe": {
            "start": format_bundle_local_timestamp(
                log_window["start_dt"],
                bundle_timezone,
                bundle_timezone_name,
            ),
            "end": format_bundle_local_timestamp(
                log_window["end_dt"],
                bundle_timezone,
                bundle_timezone_name,
            ),
        },
    }


def extract_cisco_secure_client_version_from_bundle(root_dir):
    core_log_paths = find_module_log_text_files(root_dir, "Core")
    version_patterns = [
        re.compile(
            r"Cisco Secure Client\s*-\s*GUI started.*?Version\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
            re.IGNORECASE,
        ),
        re.compile(
            r"version\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+release",
            re.IGNORECASE,
        ),
        re.compile(
            r"Product Version\s+'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'",
            re.IGNORECASE,
        ),
    ]

    for log_path in core_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    for pattern in version_patterns:
                        match = pattern.search(line)
                        if match:
                            return match.group(1)
        except OSError:
            continue

    # If Core logs don't expose product version, try ZTA agent logs.
    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    zta_version_patterns = [
        re.compile(r"ZTA\s+Agent\s+Version\s+[\"']([0-9]+(?:\.[0-9]+){1,3})[\"']", re.IGNORECASE),
        re.compile(r"\"client\"\s*:\s*\{[^\n\r]*?\"version\"\s*:\s*\"([0-9]+(?:\.[0-9]+){1,3})\"", re.IGNORECASE),
    ]

    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    for pattern in zta_version_patterns:
                        match = pattern.search(line)
                        if match:
                            return match.group(1)
        except OSError:
            continue

    # Some bundles do not include product version in Core logs. Fall back to
    # profile XML/install logs where acversion/version keys are recorded.
    fallback_patterns = [
        re.compile(r"\bacversion\s*=\s*[\"']([0-9]+(?:\.[0-9]+){1,3})[\"']", re.IGNORECASE),
        re.compile(r"\bproduct\s*version\s*[:=]\s*[\"']?([0-9]+(?:\.[0-9]+){1,3})", re.IGNORECASE),
        re.compile(r"\bversion\s*[:=]\s*[\"']([0-9]+(?:\.[0-9]+){1,3})[\"']", re.IGNORECASE),
    ]

    fallback_files = []
    for current_root, _, files in os.walk(root_dir):
        normalized_root = current_root.lower().replace("_", " ")
        if "__macosx" in current_root.lower():
            continue
        if "cisco secure client" not in normalized_root:
            continue
        if "core" not in normalized_root:
            continue

        for filename in files:
            lowered_name = filename.lower()
            if filename.startswith("._"):
                continue
            if lowered_name == "anyconnectlocalpolicy.xml":
                fallback_files.insert(0, os.path.join(current_root, filename))
                continue
            if "updatehistory" in lowered_name and lowered_name.endswith(".txt"):
                fallback_files.append(os.path.join(current_root, filename))
                continue
            if lowered_name in {"update.txt", "vpnmanifest.dat"}:
                fallback_files.append(os.path.join(current_root, filename))

    for file_path in fallback_files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
        except OSError:
            continue

        for pattern in fallback_patterns:
            match = pattern.search(content)
            if match:
                return match.group(1)

    return "Unknown"


def extract_component_version_from_module_logs(root_dir, module_folder_name, version_patterns):
    log_paths = find_module_log_text_files(root_dir, module_folder_name)
    if not log_paths:
        return "Unknown"

    compiled_patterns = [
        re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern
        for pattern in version_patterns
    ]

    def parse_version_tuple(version_text):
        parts = [segment for segment in str(version_text or "").strip().split(".") if segment != ""]
        if not parts:
            return None
        try:
            normalized = [int(part) for part in parts]
        except ValueError:
            return None

        # Normalize to 4 segments for consistent comparison (major.minor.patch.build).
        while len(normalized) < 4:
            normalized.append(0)
        return tuple(normalized[:4])

    matched_versions = []

    for log_path in log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    for pattern in compiled_patterns:
                        match = pattern.search(line)
                        if match:
                            version_value = str(match.group(1) or "").strip()
                            if version_value:
                                matched_versions.append(version_value)
        except OSError:
            continue

    if matched_versions:
        ranked_versions = []
        for version_value in matched_versions:
            parsed_tuple = parse_version_tuple(version_value)
            if parsed_tuple is not None:
                ranked_versions.append((parsed_tuple, version_value))

        if ranked_versions:
            ranked_versions.sort(key=lambda item: item[0], reverse=True)
            return ranked_versions[0][1]

        # Fallback for non-numeric variants: use the last observed version text.
        return matched_versions[-1]

    return "Unknown"


def extract_component_versions_from_bundle(root_dir):
    zta_version = extract_component_version_from_module_logs(
        root_dir,
        "Zero Trust Access",
        [
            r"\bZTA\s+Agent\s+Version\s*[\"']?([0-9]+(?:\.[0-9]+){1,3})[\"']?",
            r"\bcsc_zta_agent\b.*?\bversion\b[^0-9]*([0-9]+(?:\.[0-9]+){1,3})",
            r"\bZero\s+Trust\s+Access\b.*?\bversion\b[^0-9]*([0-9]+(?:\.[0-9]+){1,3})",
        ],
    )

    vpn_version = extract_component_version_from_module_logs(
        root_dir,
        "AnyConnect VPN",
        [
            r"\bvpnapi\s+version\s+([0-9]+(?:\.[0-9]+){1,3})",
            r"\bVPN\s+Agent\s+Version\s*[\"']?([0-9]+(?:\.[0-9]+){1,3})[\"']?",
            r"\bcsc_vpn\w*\b.*?\bversion\b[^0-9]*([0-9]+(?:\.[0-9]+){1,3})",
        ],
    )

    umbrella_version = extract_component_version_from_module_logs(
        root_dir,
        "Umbrella",
        [
            r"\bUmbrella\s+Agent\s+Version\s*[\"']?([0-9]+(?:\.[0-9]+){1,3})[\"']?",
            r"\bcsc_umbrella\w*\b.*?\bversion\b[^0-9]*([0-9]+(?:\.[0-9]+){1,3})",
        ],
    )

    return {
        "zta_version": zta_version,
        "vpn_version": vpn_version,
        "umbrella_version": umbrella_version,
    }


def parse_log_timestamp(timestamp_text):
    text = str(timestamp_text).strip()
    if not text:
        return None

    for pattern in (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
    ):
        try:
            parsed = datetime.strptime(text, pattern)
            return parsed.replace(tzinfo=None)
        except ValueError:
            continue

    for pattern in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            return datetime.strptime(text, pattern)
        except ValueError:
            continue

    return None


def find_event_viewer_evtx_files(root_dir):
    channels = {
        "Application": [],
        "System": [],
        "ZTA": [],
    }

    for current_root, _, files in os.walk(root_dir):
        lowered_root = current_root.lower()
        if "__macosx" in lowered_root:
            continue

        for filename in files:
            if filename.startswith("._"):
                continue
            lowered_name = filename.lower()
            if not lowered_name.endswith(".evtx"):
                continue

            full_path = os.path.join(current_root, filename)
            compact_name = re.sub(r"[^a-z0-9]", "", lowered_name)
            if "application" in compact_name:
                channels["Application"].append(full_path)
            elif "system" in compact_name:
                channels["System"].append(full_path)
            elif "zta" in compact_name or "zerotrustaccess" in compact_name:
                channels["ZTA"].append(full_path)

    channels["Application"] = sorted(set(channels["Application"]))
    channels["System"] = sorted(set(channels["System"]))
    channels["ZTA"] = sorted(set(channels["ZTA"]))
    return channels


def normalize_event_time(system_time_text):
    text = str(system_time_text or "").strip()
    if not text:
        return None

    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo:
        return parsed.astimezone().replace(tzinfo=None)
    return parsed


def map_windows_event_level(level_value):
    mapping = {
        1: "Critical",
        2: "Error",
        3: "Warning",
        4: "Information",
        5: "Verbose",
    }
    return mapping.get(level_value, "Unknown")


def parse_evtx_record_xml(xml_text, channel_hint=""):
    provider_match = re.search(r'<Provider[^>]*Name="([^"]+)"', xml_text)
    event_id_match = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml_text)
    level_match = re.search(r"<Level>(\d+)</Level>", xml_text)
    channel_match = re.search(r"<Channel>([^<]+)</Channel>", xml_text)
    time_match = re.search(r'<TimeCreated[^>]*SystemTime="([^"]+)"', xml_text)
    computer_match = re.search(r"<Computer>([^<]+)</Computer>", xml_text)
    data_matches = re.findall(r"<Data[^>]*>(.*?)</Data>", xml_text, flags=re.IGNORECASE | re.DOTALL)

    level_value = int(level_match.group(1)) if level_match else 0
    level_name = map_windows_event_level(level_value)
    event_time = normalize_event_time(time_match.group(1) if time_match else "")

    cleaned_values = []
    for item in data_matches:
        compact = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", str(item))).strip()
        if compact:
            cleaned_values.append(compact)

    message_preview = "; ".join(cleaned_values[:2])

    return {
        "provider": provider_match.group(1) if provider_match else "Unknown",
        "event_id": int(event_id_match.group(1)) if event_id_match else 0,
        "level": level_name,
        "channel": channel_match.group(1) if channel_match else channel_hint,
        "timestamp": event_time,
        "timestamp_text": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else "Unknown",
        "computer": computer_match.group(1) if computer_match else "Unknown",
        "message_preview": message_preview,
    }


def scan_evtx_channels(root_dir, level_filter=None, max_records_per_file=None, channels=None):
    try:
        evtx_module = importlib.import_module("Evtx.Evtx")
        EvtxReader = getattr(evtx_module, "Evtx", None)
    except Exception:
        EvtxReader = None

    channel_paths = find_event_viewer_evtx_files(root_dir)
    if channels:
        allowed = {str(name).strip() for name in channels}
        channel_paths = {name: paths for name, paths in channel_paths.items() if name in allowed}
    if not any(channel_paths.values()):
        return {
            "events": [],
            "files": channel_paths,
            "error": "No Application/System/ZTA EVTX files were found.",
        }
    if EvtxReader is None:
        return {
            "events": [],
            "files": channel_paths,
            "error": "EVTX parser dependency is unavailable. Install python-evtx.",
        }

    normalized_levels = {str(level).strip().lower() for level in (level_filter or []) if str(level).strip()}
    events = []

    for channel_name, paths in channel_paths.items():
        for evtx_path in paths:
            scanned = 0
            try:
                with EvtxReader(evtx_path) as evtx_handle:
                    for record in evtx_handle.records():
                        scanned += 1
                        if max_records_per_file and scanned > max_records_per_file:
                            break
                        parsed = parse_evtx_record_xml(record.xml(), channel_hint=channel_name)
                        if normalized_levels and parsed["level"].lower() not in normalized_levels:
                            continue
                        parsed["path"] = evtx_path
                        events.append(parsed)
            except Exception:
                continue

    return {
        "events": events,
        "files": channel_paths,
        "error": None,
    }


def summarize_event_viewer_events(events, sample_limit=20):
    level_counts = Counter(event["level"] for event in events)
    provider_counts = Counter(event["provider"] for event in events)
    event_id_counts = Counter(event["event_id"] for event in events if event.get("event_id"))

    sorted_events = sorted(
        events,
        key=lambda item: item["timestamp"] if item.get("timestamp") else datetime.min,
        reverse=True,
    )

    return {
        "total": len(events),
        "levels": dict(level_counts),
        "top_providers": provider_counts.most_common(8),
        "top_event_ids": event_id_counts.most_common(8),
        "samples": sorted_events[:sample_limit],
    }


def correlate_events_by_time(events, anchor_timestamps, window_minutes=4, sample_limit=15):
    anchors = [stamp for stamp in (anchor_timestamps or []) if stamp is not None]
    if not anchors:
        return []

    window_seconds = int(window_minutes * 60)
    correlated = []
    for event in events:
        event_dt = event.get("timestamp")
        if event_dt is None:
            continue
        for anchor in anchors:
            if abs((event_dt - anchor).total_seconds()) <= window_seconds:
                correlated.append(event)
                break

    correlated_sorted = sorted(
        correlated,
        key=lambda item: item["timestamp"] if item.get("timestamp") else datetime.min,
        reverse=True,
    )
    return correlated_sorted[:sample_limit]


def parse_ui_datetime_local(value):
    text = str(value or "").strip()
    if not text:
        return None

    normalized = text.replace("Z", "")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def to_bundle_local_datetime(ui_datetime, client_timezone_offset_minutes, bundle_timezone):
    if ui_datetime is None:
        return None

    try:
        offset_minutes = int(str(client_timezone_offset_minutes).strip())
    except (TypeError, ValueError):
        return ui_datetime

    utc_datetime = (ui_datetime + timedelta(minutes=offset_minutes)).replace(tzinfo=timezone.utc)
    bundle_datetime = utc_datetime.astimezone(bundle_timezone)
    return bundle_datetime.replace(tzinfo=None)


def format_bundle_filter_datetime(value, bundle_timezone, bundle_timezone_name):
    if value is None:
        return "Any"

    return value.replace(tzinfo=bundle_timezone).strftime(
        f"%Y-%m-%d %H:%M:%S {bundle_timezone_name}"
    )


def format_bundle_local_timestamp(timestamp_value, bundle_timezone, bundle_timezone_name):
    if timestamp_value is None:
        return None

    localized = timestamp_value.replace(tzinfo=bundle_timezone)
    return localized.strftime(f"%Y-%m-%d %H:%M:%S {bundle_timezone_name}")


def split_timestamp_and_timezone(value):
    text = str(value or "").strip()
    if not text:
        return {
            "timestamp": "",
            "timezone": "",
        }

    match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.+)$", text)
    if not match:
        return {
            "timestamp": text,
            "timezone": "",
        }

    return {
        "timestamp": match.group(1),
        "timezone": match.group(2),
    }


def update_log_window_bounds(log_window, timestamp_text):
    parsed_timestamp = parse_log_timestamp(timestamp_text)
    if parsed_timestamp is None:
        return

    if not log_window["start_dt"] or parsed_timestamp < log_window["start_dt"]:
        log_window["start_dt"] = parsed_timestamp
    if not log_window["end_dt"] or parsed_timestamp > log_window["end_dt"]:
        log_window["end_dt"] = parsed_timestamp


def extract_log_time_window_bounds(log_paths):
    log_window = {
        "start_dt": None,
        "end_dt": None,
    }
    iso_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
    date_pattern = re.compile(r"\s*Date\s*:\s*(\d{2}/\d{2}/\d{4})")
    time_pattern = re.compile(r"\s*Time\s*:\s*(\d{2}:\d{2}:\d{2})")

    for log_path in log_paths:
        pending_date = None
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    for match in iso_pattern.finditer(raw_line):
                        update_log_window_bounds(log_window, match.group(1))

                    date_match = date_pattern.match(raw_line)
                    if date_match:
                        pending_date = date_match.group(1)
                        continue

                    time_match = time_pattern.match(raw_line)
                    if time_match and pending_date:
                        update_log_window_bounds(
                            log_window,
                            f"{pending_date} {time_match.group(1)}",
                        )
                        pending_date = None
        except OSError:
            continue

    return log_window


def extract_log_time_window(log_paths, bundle_timezone, bundle_timezone_name):
    log_window = extract_log_time_window_bounds(log_paths)

    return {
        "start": format_bundle_local_timestamp(
            log_window["start_dt"],
            bundle_timezone,
            bundle_timezone_name,
        ),
        "end": format_bundle_local_timestamp(
            log_window["end_dt"],
            bundle_timezone,
            bundle_timezone_name,
        ),
    }


def extract_duo_match_time_window(matches, bundle_timezone, bundle_timezone_name):
    log_window = {
        "start_dt": None,
        "end_dt": None,
    }
    iso_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)")
    slash_pattern = re.compile(r"(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})")

    for match in matches:
        line_text = str(match.get("line", ""))
        for timestamp_match in iso_pattern.finditer(line_text):
            update_log_window_bounds(log_window, timestamp_match.group(1))
        for timestamp_match in slash_pattern.finditer(line_text):
            update_log_window_bounds(log_window, timestamp_match.group(1))

    return {
        "start": format_bundle_local_timestamp(
            log_window["start_dt"],
            bundle_timezone,
            bundle_timezone_name,
        ),
        "end": format_bundle_local_timestamp(
            log_window["end_dt"],
            bundle_timezone,
            bundle_timezone_name,
        ),
    }


def summarize_duo_match_lines(matches, max_items=40):
    # Collapse repetitive lines while preserving representative content.
    summary_map = {}
    iso_prefix_pattern = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?\s*")
    slash_prefix_pattern = re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\s*")
    numeric_error_pattern = re.compile(r"(?:\|)?\s*Error\s*:\s*\d+\b", re.IGNORECASE)

    for match in matches:
        raw_line = str(match.get("line", "")).strip()
        if not raw_line:
            continue

        display_line = numeric_error_pattern.sub("", raw_line).rstrip(" |")
        display_line = re.sub(r"\s{2,}", " ", display_line).strip()

        normalized = iso_prefix_pattern.sub("", raw_line)
        normalized = slash_prefix_pattern.sub("", normalized)
        normalized = numeric_error_pattern.sub("", normalized)
        normalized = normalized.strip(" -:\t")
        key = normalized or raw_line

        if key not in summary_map:
            summary_map[key] = {
                "count": 0,
                "sample": display_line or raw_line,
            }
        summary_map[key]["count"] += 1

    condensed = sorted(
        summary_map.values(),
        key=lambda item: (-item["count"], item["sample"].lower()),
    )
    return condensed[:max_items]


def format_timeframe_single_timezone(start_text, end_text):
    if not start_text or not end_text:
        return None

    tz_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+([A-Za-z][A-Za-z ]+)$")
    start_match = tz_pattern.match(str(start_text).strip())
    end_match = tz_pattern.match(str(end_text).strip())

    if start_match and end_match and start_match.group(2) == end_match.group(2):
        timezone_name = end_match.group(2)
        return f"{start_match.group(1)} -> {end_match.group(1)} {timezone_name}"

    return f"{start_text} -> {end_text}"


def is_zta_trace_level_logging_enabled(root_dir):
    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    level_pattern = re.compile(r"\]\s+([A-Z])/")

    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    level_match = level_pattern.search(raw_line)
                    if not level_match:
                        continue
                    if level_match.group(1) == "T":
                        return True
        except OSError:
            continue

    return False


def extract_bundle_preview_metadata(root_dir, include_log_windows=True, include_component_versions=True):
    bundle_timezone, bundle_timezone_name = resolve_bundle_timezone(root_dir)
    if include_component_versions:
        component_versions = extract_component_versions_from_bundle(root_dir)
        cisco_secure_client_version = extract_cisco_secure_client_version_from_bundle(root_dir)
        zta_trace_level_logging_enabled = is_zta_trace_level_logging_enabled(root_dir)
    else:
        component_versions = {
            "zta_version": "Unknown",
            "vpn_version": "Unknown",
            "umbrella_version": "Unknown",
        }
        cisco_secure_client_version = "Unknown"
        zta_trace_level_logging_enabled = None

    zta_logs = {"start": "Not found", "end": "Not found"}
    duo_logs = {"start": "Not found", "end": "Not found"}
    vpn_logs = {"start": "Not found", "end": "Not found"}
    umbrella_logs = {"start": "Not found", "end": "Not found"}

    if include_log_windows:
        zta_logs = extract_log_time_window(
            find_module_log_text_files(root_dir, "Zero Trust Access"),
            bundle_timezone,
            bundle_timezone_name,
        )
        duo_logs = extract_log_time_window(
            find_duo_desktop_user_log_files(root_dir),
            bundle_timezone,
            bundle_timezone_name,
        )
        vpn_logs = extract_log_time_window(
            find_module_log_text_files(root_dir, "AnyConnect VPN"),
            bundle_timezone,
            bundle_timezone_name,
        )
        umbrella_logs = extract_log_time_window(
            find_module_log_text_files(root_dir, "Umbrella"),
            bundle_timezone,
            bundle_timezone_name,
        )
        zta_preview_signals = build_zta_preview_signals(root_dir)
    else:
        zta_logs["skipped"] = True
        duo_logs["skipped"] = True
        vpn_logs["skipped"] = True
        umbrella_logs["skipped"] = True
        zta_preview_signals = {"available": False, "skipped": True}

    return {
        "cisco_secure_client_version": cisco_secure_client_version,
        "zta_version": component_versions["zta_version"],
        "vpn_version": component_versions["vpn_version"],
        "umbrella_version": component_versions["umbrella_version"],
        "operating_system": extract_operating_system_from_bundle(root_dir),
        "duo_desktop_detailed_logging_enabled": is_duo_desktop_detailed_logging_enabled(root_dir),
        "duo_desktop_user_folders": get_duo_desktop_user_folders(root_dir),
        "zta_trace_level_logging_enabled": zta_trace_level_logging_enabled,
        "zta_logs": zta_logs,
        "duo_logs": duo_logs,
        "vpn_logs": vpn_logs,
        "umbrella_logs": umbrella_logs,
        "zta_preview_signals": zta_preview_signals,
    }


def inspect_bundle_for_org_ids(file_storage, prefix="darthawk_inspect_", include_log_windows=True, include_component_versions=True):
    temp_dir = tempfile.mkdtemp(prefix=prefix)
    zip_path = os.path.join(temp_dir, file_storage.filename or "bundle.zip")
    file_storage.save(zip_path)

    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        org_id_results = extract_org_ids_from_enrollments(temp_dir)
        preview_metadata = extract_bundle_preview_metadata(
            temp_dir,
            include_log_windows=include_log_windows,
            include_component_versions=include_component_versions,
        )
        return {
            "org_ids": org_id_results["org_ids"],
            "user_ids": org_id_results["user_ids"],
            "numeric_user_ids": org_id_results["numeric_user_ids"],
            "enrollment_methods": org_id_results["enrollment_methods"],
            "enrollment_times": org_id_results["enrollment_times"],
            "enrollment_urls": org_id_results["enrollment_urls"],
            "warnings": org_id_results["warnings"],
            "cisco_secure_client_version": preview_metadata["cisco_secure_client_version"],
            "zta_version": preview_metadata["zta_version"],
            "vpn_version": preview_metadata["vpn_version"],
            "umbrella_version": preview_metadata["umbrella_version"],
            "operating_system": preview_metadata["operating_system"],
            "duo_desktop_detailed_logging_enabled": preview_metadata["duo_desktop_detailed_logging_enabled"],
            "duo_desktop_user_folders": preview_metadata["duo_desktop_user_folders"],
            "zta_trace_level_logging_enabled": preview_metadata["zta_trace_level_logging_enabled"],
            "zta_logs": preview_metadata["zta_logs"],
            "duo_logs": preview_metadata["duo_logs"],
            "vpn_logs": preview_metadata["vpn_logs"],
            "umbrella_logs": preview_metadata["umbrella_logs"],
            "zta_preview_signals": preview_metadata.get("zta_preview_signals"),
            "lightweight_inspect": not include_log_windows,
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def collect_values_from_json(candidate, key_matcher):
    collected = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key_matcher(str(key)):
                    collected.extend(flatten_to_strings(value))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    def flatten_to_strings(node):
        values = []
        if isinstance(node, str):
            values.append(node.strip())
        elif isinstance(node, list):
            for item in node:
                values.extend(flatten_to_strings(item))
        elif isinstance(node, dict):
            for _, value in node.items():
                values.extend(flatten_to_strings(value))
        return values

    walk(candidate)
    return [value for value in collected if value]


def is_ip_entry(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_fqdn_entry(value):
    fqdn_pattern = re.compile(r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
    return bool(fqdn_pattern.match(value))


def zta_mode_keywords(zta_access_mode):
    if zta_access_mode == "SPA":
        return ["spa", "secure private access", "private access"]
    return ["sia", "secure internet access", "internet access"]


def find_mode_sections(candidate, keywords):
    matches = []

    def has_keyword(text):
        lowered = str(text).lower()
        return any(keyword in lowered for keyword in keywords)

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if has_keyword(key):
                    matches.append(value)
                if isinstance(value, (dict, list)):
                    walk(value)

            # Match objects where metadata identifies SPA/SIA.
            node_text = " ".join(str(node.get(field, "")) for field in ["name", "display_name", "type", "service"])
            if node_text and has_keyword(node_text):
                matches.append(node)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(candidate)
    return matches


def extract_zta_values_from_json(json_path, zta_access_mode):
    with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
        payload = json.load(handle)

    keywords = zta_mode_keywords(zta_access_mode)
    sections = find_mode_sections(payload, keywords)
    scoped_values = []

    # Focus on exclusion-related keys under the selected SPA/SIA scope.
    exclusion_key_matcher = lambda key: "exclude" in key.lower() or "exclusion" in key.lower()
    for section in sections:
        scoped_values.extend(collect_values_from_json(section, exclusion_key_matcher))

    unique_values = sorted(set(value for value in scoped_values if value))
    ip_values = [value for value in unique_values if is_ip_entry(value)]
    fqdn_values = [value for value in unique_values if is_fqdn_entry(value)]
    other_values = [value for value in unique_values if value not in ip_values and value not in fqdn_values]
    return {
        "matched_sections": len(sections),
        "ip_exclusions": ip_values,
        "fqdn_exclusions": fqdn_values,
        "other_exclusions": other_values,
    }


def collect_keyed_values(candidate, key_tokens):
    collected = []

    def flatten_to_strings(node):
        values = []
        if isinstance(node, str):
            stripped = node.strip()
            if stripped:
                values.append(stripped)
        elif isinstance(node, (bool, int, float)):
            values.append(str(node))
        elif isinstance(node, list):
            for item in node:
                values.extend(flatten_to_strings(item))
        elif isinstance(node, dict):
            for _, value in node.items():
                values.extend(flatten_to_strings(value))
        return values

    def key_matches(key):
        normalized = str(key).lower().replace("_", " ").replace("-", " ")
        return all(token in normalized for token in key_tokens)

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key_matches(key):
                    collected.extend(flatten_to_strings(value))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(candidate)
    return sorted(set(value for value in collected if value))


def collect_trusted_network_detection_configs(payload, flow_filter=None):
    default_configs = [
        {
            "flow": "SPA",
            "proxy_config_id": "default_spa_config",
            "proxy_config_label": "Secure Private Access",
        },
        {
            "flow": "SIA",
            "proxy_config_id": "default_tia_config",
            "proxy_config_label": "Secure Internet Access",
        },
    ]

    def normalize_key_tokens(key_name):
        # Normalize snake_case, kebab-case, and camelCase to tokenized lowercase text.
        key_text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key_name))
        key_text = key_text.replace("_", " ").replace("-", " ").lower()
        key_text = re.sub(r"\s+", " ", key_text).strip()
        return key_text

    def flatten_to_strings(node):
        values = []
        if isinstance(node, str):
            stripped = node.strip()
            if stripped:
                values.append(stripped)
        elif isinstance(node, (bool, int, float)):
            values.append(str(node))
        elif isinstance(node, list):
            for item in node:
                values.extend(flatten_to_strings(item))
        elif isinstance(node, dict):
            for _, value in node.items():
                values.extend(flatten_to_strings(value))
        return values

    def collect_criteria(node):
        criteria = {
            "dns_servers": set(),
            "domains": set(),
            "trusted_servers": set(),
        }

        def walk(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    normalized_key = str(key).lower().replace("_", " ").replace("-", " ")
                    flattened = flatten_to_strings(value)
                    if "dns" in normalized_key and ("server" in normalized_key or "servers" in normalized_key or normalized_key.strip() == "dns"):
                        criteria["dns_servers"].update(flattened)
                    if "domain" in normalized_key:
                        criteria["domains"].update(flattened)
                    if "trusted" in normalized_key and "server" in normalized_key:
                        criteria["trusted_servers"].update(flattened)
                    walk(value)
            elif isinstance(item, list):
                for entry in item:
                    walk(entry)

        walk(node)
        return criteria

    def collect_match_fingerprint_refs(node):
        refs = []

        def key_matches(key_name):
            normalized_key = normalize_key_tokens(key_name)
            return "fingerprint" in normalized_key and "match" in normalized_key

        def walk(item):
            if isinstance(item, str):
                stripped = item.strip()
                if stripped:
                    refs.append(stripped)
            elif isinstance(item, list):
                for entry in item:
                    walk(entry)
            elif isinstance(item, dict):
                for key, value in item.items():
                    if key_matches(key):
                        refs.extend(flatten_to_strings(value))
                    else:
                        walk(value)

        walk(node)
        return refs

    def collect_values_by_key_tokens(node, required_tokens):
        values = []

        def key_matches(key_name):
            normalized_key = normalize_key_tokens(key_name)
            return all(token in normalized_key for token in required_tokens)

        def walk(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    if key_matches(key):
                        values.append(value)
                    walk(value)
            elif isinstance(item, list):
                for entry in item:
                    walk(entry)

        walk(node)
        return values

    def collect_conditional_actions(node):
        values = set()

        def is_default_connect_action(action_text):
            text = str(action_text or "").strip().lower()
            if not text:
                return False
            if "action=connect" not in text:
                return False

            # Treat bare connect as default config noise and ignore it.
            has_check_type = "check_type=" in text
            has_match_fingerprints = "match_network_fingerprints=" in text
            return not has_check_type and not has_match_fingerprints

        def format_conditional_action(entry):
            if not isinstance(entry, dict):
                return ""

            action_value = first_non_empty_value(
                entry,
                ["action", "action_type", "match_action", "on_match_action", "policy_action"],
            )
            check_type_value = first_non_empty_value(entry, ["check_type", "checkType", "type"])
            fingerprint_refs = [
                ref
                for ref in collect_match_fingerprint_refs(entry)
                if isinstance(ref, str) and re.fullmatch(r"[0-9a-fA-F-]{16,}", ref.strip())
            ]

            parts = []
            if action_value:
                parts.append(f"action={action_value}")
            if check_type_value:
                parts.append(f"check_type={check_type_value}")
            if fingerprint_refs:
                parts.append(
                    "match_network_fingerprints="
                    + ",".join(sorted({str(ref).strip() for ref in fingerprint_refs if str(ref).strip()}))
                )

            return ", ".join(parts)

        def walk(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    normalized_key = normalize_key_tokens(key)
                    if (
                        "conditional" in normalized_key
                        and "action" in normalized_key
                        and value not in (None, "", [], {})
                    ):
                        if isinstance(value, list):
                            for conditional_entry in value:
                                rendered = format_conditional_action(conditional_entry)
                                if rendered and not is_default_connect_action(rendered):
                                    values.add(rendered)
                        elif isinstance(value, dict):
                            rendered = format_conditional_action(value)
                            if rendered and not is_default_connect_action(rendered):
                                values.add(rendered)
                    walk(value)
            elif isinstance(item, list):
                for entry in item:
                    walk(entry)

        walk(node)
        return values

    def collect_global_network_fingerprints(node):
        fingerprint_blocks = []

        def walk(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    normalized_key = normalize_key_tokens(key)
                    if (
                        "network" in normalized_key
                        and "fingerprint" in normalized_key
                        and value not in (None, "", [], {})
                    ):
                        fingerprint_blocks.append(value)
                    walk(value)
            elif isinstance(item, list):
                for entry in item:
                    walk(entry)

        walk(node)
        return fingerprint_blocks

    def first_non_empty_value(node, candidate_keys):
        if not isinstance(node, dict):
            return ""
        for key in candidate_keys:
            if key in node and node[key] not in (None, ""):
                value_text = str(node[key]).strip()
                if value_text:
                    return value_text
        return ""

    def index_objects_by_id(node, id_index):
        if isinstance(node, dict):
            candidate_ids = set()
            for key_name in ("id", "name", "fingerprint_id", "fingerprintId"):
                value = node.get(key_name)
                if value in (None, "", [], {}):
                    continue
                text = str(value).strip()
                if text:
                    candidate_ids.add(text)
            for object_id in candidate_ids:
                id_index.setdefault(object_id, []).append(node)
            for value in node.values():
                index_objects_by_id(value, id_index)
        elif isinstance(node, list):
            for entry in node:
                index_objects_by_id(entry, id_index)

    id_index = {}
    index_objects_by_id(payload, id_index)
    global_fingerprint_blocks = collect_global_network_fingerprints(payload)

    target_configs = [config for config in default_configs if not flow_filter or config["flow"] == flow_filter]

    config_results = []
    for default_config in target_configs:
        config_id = default_config["proxy_config_id"]
        config_objects = id_index.get(config_id, [])
        configured = False
        conditional_actions = set()
        all_refs = set()
        all_dns_servers = set()
        all_domains = set()
        all_trusted_servers = set()

        for config_object in config_objects:
            match_values = []
            direct_match_value = config_object.get("match_network_fingerprint")
            if direct_match_value not in (None, "", [], {}):
                match_values.append(direct_match_value)

            nested_match_values = collect_values_by_key_tokens(
                config_object,
                ["match", "network", "fingerprint"],
            )
            match_values.extend(
                value for value in nested_match_values if value not in (None, "", [], {})
            )

            network_fingerprint_values = []
            direct_fingerprints = config_object.get("network_fingerprints")
            if direct_fingerprints not in (None, "", [], {}):
                network_fingerprint_values.append(direct_fingerprints)

            nested_fingerprint_values = collect_values_by_key_tokens(
                config_object,
                ["network", "fingerprint"],
            )
            network_fingerprint_values.extend(
                value for value in nested_fingerprint_values if value not in (None, "", [], {})
            )

            if network_fingerprint_values:
                configured = True
                for fingerprint_block in network_fingerprint_values:
                    fingerprint_criteria = collect_criteria(fingerprint_block)
                    all_dns_servers.update(fingerprint_criteria["dns_servers"])
                    all_domains.update(fingerprint_criteria["domains"])
                    all_trusted_servers.update(fingerprint_criteria["trusted_servers"])

                    block_refs = collect_match_fingerprint_refs(fingerprint_block)
                    for ref in block_refs:
                        if isinstance(ref, str) and re.fullmatch(r"[0-9a-fA-F-]{16,}", ref.strip()):
                            all_refs.add(ref.strip())

                    if isinstance(fingerprint_block, list):
                        for fingerprint_entry in fingerprint_block:
                            if isinstance(fingerprint_entry, dict):
                                fingerprint_id = str(fingerprint_entry.get("id", "")).strip()
                                if fingerprint_id:
                                    all_refs.add(fingerprint_id)
                    elif isinstance(fingerprint_block, dict):
                        fingerprint_id = str(fingerprint_block.get("id", "")).strip()
                        if fingerprint_id:
                            all_refs.add(fingerprint_id)

            if match_values:
                configured = True

                for match_value in match_values:
                    direct_criteria = collect_criteria(match_value)
                    all_dns_servers.update(direct_criteria["dns_servers"])
                    all_domains.update(direct_criteria["domains"])
                    all_trusted_servers.update(direct_criteria["trusted_servers"])

                    refs = collect_match_fingerprint_refs(match_value)
                    for ref in refs:
                        matched_objects = id_index.get(ref, [])
                        if not matched_objects:
                            lowered_ref = str(ref).lower()
                            for indexed_id, indexed_objects in id_index.items():
                                if str(indexed_id).lower() == lowered_ref:
                                    matched_objects = indexed_objects
                                    break
                        if not matched_objects:
                            continue

                        all_refs.add(str(ref))
                        for fingerprint_object in matched_objects:
                            fingerprint_criteria = collect_criteria(fingerprint_object)
                            all_dns_servers.update(fingerprint_criteria["dns_servers"])
                            all_domains.update(fingerprint_criteria["domains"])
                            all_trusted_servers.update(fingerprint_criteria["trusted_servers"])

            for fingerprint_key in (
                "network_fingerprint",
                "network_fingerprints",
                "trusted_network_detection",
                "trusted_network_fingerprints",
            ):
                fingerprint_value = config_object.get(fingerprint_key)
                if fingerprint_value in (None, "", [], {}):
                    continue
                configured = True
                fingerprint_criteria = collect_criteria(fingerprint_value)
                all_dns_servers.update(fingerprint_criteria["dns_servers"])
                all_domains.update(fingerprint_criteria["domains"])
                all_trusted_servers.update(fingerprint_criteria["trusted_servers"])

            conditional_actions.update(collect_conditional_actions(config_object))

        # Some bundles define network_fingerprints globally under ztnaConfig
        # and do not wire explicit match_network_fingerprint on default_spa_config.
        if global_fingerprint_blocks:
            configured = True
            for fingerprint_block in global_fingerprint_blocks:
                fingerprint_criteria = collect_criteria(fingerprint_block)
                all_dns_servers.update(fingerprint_criteria["dns_servers"])
                all_domains.update(fingerprint_criteria["domains"])
                all_trusted_servers.update(fingerprint_criteria["trusted_servers"])

                if isinstance(fingerprint_block, list):
                    for fingerprint_entry in fingerprint_block:
                        if isinstance(fingerprint_entry, dict):
                            fingerprint_id = str(fingerprint_entry.get("id", "")).strip()
                            if fingerprint_id:
                                all_refs.add(fingerprint_id)
                elif isinstance(fingerprint_block, dict):
                    fingerprint_id = str(fingerprint_block.get("id", "")).strip()
                    if fingerprint_id:
                        all_refs.add(fingerprint_id)

        config_results.append(
            {
                **default_config,
                "proxy_config_found": bool(config_objects),
                "match_network_fingerprint_configured": configured,
                "conditional_actions": sorted(conditional_actions),
                "matched_fingerprint_refs": sorted(all_refs),
                "dns_servers": sorted(all_dns_servers),
                "domains": sorted(all_domains),
                "trusted_servers": sorted(all_trusted_servers),
            }
        )

    return config_results


def extract_spa_trusted_network_detection(json_path, flow_filter=None):
    with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
        payload = json.load(handle)
    return collect_trusted_network_detection_configs(payload, flow_filter=flow_filter)


def extract_spa_user_pause_config(json_path, flow_filter=None):
    def normalize_key_tokens(key_name):
        key_text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key_name))
        key_text = key_text.replace("_", " ").replace("-", " ").lower()
        key_text = re.sub(r"\s+", " ", key_text).strip()
        return key_text

    def flatten_to_strings(node):
        values = []
        if isinstance(node, str):
            stripped = node.strip()
            if stripped:
                values.append(stripped)
        elif isinstance(node, (bool, int, float)):
            values.append(str(node))
        elif isinstance(node, list):
            for item in node:
                values.extend(flatten_to_strings(item))
        elif isinstance(node, dict):
            for _, value in node.items():
                values.extend(flatten_to_strings(value))
        return values

    def key_matches_user_pause_configs(key_name):
        normalized = normalize_key_tokens(key_name)
        return "user" in normalized and "pause" in normalized and "config" in normalized

    with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
        payload = json.load(handle)

    values = []
    matched_values = []
    key_found = False

    target_flow = str(flow_filter or "").strip().upper()

    def entry_matches_flow(entry):
        if target_flow not in {"SPA", "SIA"}:
            return True

        if not isinstance(entry, dict):
            return False

        identifier = str(entry.get("id", "")).strip().lower()
        label = str(entry.get("label", "")).strip().lower()
        combined = f"{identifier} {label}"

        if target_flow == "SPA":
            return "spa" in combined
        return "tia" in combined or "sia" in combined

    def walk(node):
        nonlocal key_found
        if isinstance(node, dict):
            for key, value in node.items():
                if key_matches_user_pause_configs(key):
                    key_found = True
                    values.extend(flatten_to_strings(value))
                    if isinstance(value, list):
                        for item in value:
                            if entry_matches_flow(item):
                                matched_values.extend(flatten_to_strings(item))
                    elif isinstance(value, dict):
                        if entry_matches_flow(value):
                            matched_values.extend(flatten_to_strings(value))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)

    effective_values = matched_values if target_flow in {"SPA", "SIA"} else values
    detected = bool(matched_values) if target_flow in {"SPA", "SIA"} else key_found

    return {
        "detected": detected,
        "values": sorted(set(value for value in effective_values if value)),
    }


def parse_new_redirected_flow_line(line_text):
    line = str(line_text).strip()
    if "new redirected flow:" not in line:
        return None

    timestamp_match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)", line)
    flow_match = re.search(
        r"new redirected flow:\s+(TCP|UDP)\s+destination\s+\[([^\]]+)\]:(\d+)\s+srcPort=(\d+)",
        line,
        re.IGNORECASE,
    )
    process_match = re.search(r"process=<([^|>]+)\|PID\s+(\d+)\|user\s+([^>]+)>", line)
    parent_process_match = re.search(r"parentProcess=<([^|>]+)\|PID\s+(\d+)\|user\s+([^>]+)>", line)
    match_rule_type_match = re.search(r"matchRuleType=([^\s]+)", line)

    if not timestamp_match or not flow_match:
        return None

    protocol = flow_match.group(1).upper()
    destination = flow_match.group(2).strip()
    destination_port = flow_match.group(3).strip()
    source_port = flow_match.group(4).strip()
    real_destination_ip_match = re.search(r"realDestIpAddr=([^\s]+)", line)
    real_destination_ip = real_destination_ip_match.group(1).strip() if real_destination_ip_match else ""

    process_name = process_match.group(1).strip() if process_match else "Unknown"
    process_pid = process_match.group(2).strip() if process_match else "Unknown"
    process_user = process_match.group(3).strip() if process_match else "Unknown"

    parent_process_name = parent_process_match.group(1).strip() if parent_process_match else "Unknown"
    parent_process_pid = parent_process_match.group(2).strip() if parent_process_match else "Unknown"
    parent_process_user = parent_process_match.group(3).strip() if parent_process_match else "Unknown"

    match_rule_type = match_rule_type_match.group(1).strip() if match_rule_type_match else "Unknown"

    return {
        "timestamp": timestamp_match.group(1),
        "protocol": protocol,
        "destination": destination,
        "destination_port": destination_port,
        "source_port": source_port,
        "real_destination_ip": real_destination_ip,
        "process_name": process_name,
        "process_pid": process_pid,
        "process_user": process_user,
        "parent_process_name": parent_process_name,
        "parent_process_pid": parent_process_pid,
        "parent_process_user": parent_process_user,
        "match_rule_type": match_rule_type,
    }


def find_spa_redirected_flows(
    root_dir,
    search_term,
    destination_port_filter=None,
    timeframe_start=None,
    timeframe_end=None,
):
    normalized_search_term = str(search_term).strip().lower()
    matches = []

    if not normalized_search_term:
        return {
            "matches": [],
            "timeframe_start": None,
            "timeframe_end": None,
        }

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.strip()
                    if "new redirected flow:" not in line:
                        continue
                    if normalized_search_term not in line.lower():
                        continue

                    parsed_line = parse_new_redirected_flow_line(line)
                    if not parsed_line:
                        continue

                    if destination_port_filter:
                        if str(parsed_line.get("destination_port", "")).strip() != str(destination_port_filter).strip():
                            continue

                    parsed_line_time = parse_log_timestamp(parsed_line.get("timestamp", ""))
                    if timeframe_start and (parsed_line_time is None or parsed_line_time < timeframe_start):
                        continue
                    if timeframe_end and (parsed_line_time is None or parsed_line_time > timeframe_end):
                        continue

                    parsed_line["path"] = log_path
                    parsed_line["line_number"] = line_number
                    matches.append(parsed_line)
        except OSError:
            continue

    parsed_timestamps = [
        parse_log_timestamp(entry["timestamp"])
        for entry in matches
        if entry.get("timestamp")
    ]
    parsed_timestamps = [entry for entry in parsed_timestamps if entry is not None]

    timeframe_start = None
    timeframe_end = None
    if parsed_timestamps:
        timeframe_start = min(parsed_timestamps).strftime("%Y-%m-%d %H:%M:%S.%f")
        timeframe_end = max(parsed_timestamps).strftime("%Y-%m-%d %H:%M:%S.%f")

    return {
        "matches": matches,
        "timeframe_start": timeframe_start,
        "timeframe_end": timeframe_end,
    }


def find_zta_log_lines_by_source_port(root_dir, source_port, timeframe_start=None, timeframe_end=None):
    """Return ZTA log lines for a source port, including multiline flow blocks.

    Matching behavior:
    - Includes lines containing srcPort=<port> or flowSrcPort=<port>.
    - Includes lines containing transport flow identifiers like tcp:<port>__ or udp:<port>__.
    - Includes continuation lines that belong to a matched block until the next
      timestamped log line begins.
    """
    normalized_port = str(source_port).strip()
    if not normalized_port:
        return []

    source_port_pattern = re.compile(
        rf"(?:^|\W)(?:srcPort|flowSrcPort)={re.escape(normalized_port)}(?:\W|$)"
        rf"|\b(?:tcp|udp):{re.escape(normalized_port)}__",
        re.IGNORECASE,
    )
    timestamp_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
    matched_lines = []
    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                capture_continuation = False
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")

                    if capture_continuation:
                        if timestamp_pattern.match(line):
                            capture_continuation = False
                        else:
                            matched_lines.append(
                                {
                                    "path": log_path,
                                    "line_number": line_number,
                                    "line": line,
                                }
                            )
                            continue

                    if not source_port_pattern.search(line):
                        continue

                    timestamp_match = timestamp_pattern.match(line)
                    line_timestamp = parse_log_timestamp(timestamp_match.group(1)) if timestamp_match else None
                    if timeframe_start and (line_timestamp is None or line_timestamp < timeframe_start):
                        continue
                    if timeframe_end and (line_timestamp is None or line_timestamp > timeframe_end):
                        continue

                    matched_lines.append(
                        {
                            "path": log_path,
                            "line_number": line_number,
                            "line": line,
                        }
                    )
                    capture_continuation = True
        except OSError:
            continue

    return matched_lines


def extract_srv_attempt_identifier(line_text):
    line = str(line_text or "")

    # Primary SRV-flow correlation token appears right after startDnsRequest().
    request_token_match = re.search(
        r"\bstartDnsRequest\(\)\s+([0-9A-Fa-f]{6,16})\b",
        line,
    )
    if request_token_match:
        return request_token_match.group(1).upper()

    identifier_patterns = [
        re.compile(r"\bflowIdentifier\s*[=:]\s*(0x[0-9a-fA-F]+)", re.IGNORECASE),
        re.compile(r"\bidentifier(?:Value)?\s*[=:]\s*(0x[0-9a-fA-F]+)", re.IGNORECASE),
        re.compile(r"\bsessionIdentifier\s*[=:]\s*(0x[0-9a-fA-F]+)", re.IGNORECASE),
    ]

    for pattern in identifier_patterns:
        match = pattern.search(line)
        if match:
            return match.group(1)

    hex_values = re.findall(r"0x[0-9a-fA-F]+", line)
    if len(hex_values) >= 2:
        # Prefer the second identifier when multiple IDs exist on the same line.
        return hex_values[1]
    if hex_values:
        return hex_values[0]
    return ""


def _discover_all_srv_flow_attempts(zta_log_paths, timestamp_pattern, timeframe_start=None, timeframe_end=None):
    """Discover every DNS SRV flow in the ZTA logs without knowing the record name.

    Triggered when the user types a generic token (e.g. "SRV") into the flow filter.
    Groups lines by DnsFlowHandler identifier and keeps only handlers that issued an
    SRV (type=33) query, capturing the actual queried record name(s) for display.
    """
    handler_id_pattern = re.compile(
        r"(?:DnsFlowHandler::Start|startDnsRequest|startReadFromFlow|"
        r"handleDnsFlowReadable|OnDohRequestComplete|handleDohRequestComplete|"
        r"onRequestComplete|handleClose|~DnsFlowHandler)\(\)\s+([0-9A-Fa-f]{6,16})\b"
    )
    packet_open_pattern = re.compile(r"dns_packet\s*:\s*\{")
    qname_srv_pattern = re.compile(
        r"\[q:\s*name=(\S+)\s+class=\d+\s+type=33\s+SRV\]", re.IGNORECASE
    )
    srv_signal_pattern = re.compile(r"type=33\s+SRV|qryType=SRV", re.IGNORECASE)

    attempt_index = {}

    for log_path in zta_log_paths:
        current_id = None
        in_packet = False
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")

                    handler_match = handler_id_pattern.search(line)
                    if handler_match:
                        current_id = handler_match.group(1).upper()
                        in_packet = bool(packet_open_pattern.search(line))
                        id_for_line = current_id
                    elif in_packet and current_id:
                        # Continuation line inside the dns_packet block (e.g. the q: name line).
                        id_for_line = current_id
                    else:
                        id_for_line = None

                    if not id_for_line:
                        continue

                    timestamp_match = timestamp_pattern.match(line)
                    line_timestamp_text = timestamp_match.group(1) if timestamp_match else ""
                    line_timestamp = parse_log_timestamp(line_timestamp_text) if line_timestamp_text else None

                    attempt = attempt_index.get(id_for_line)
                    if attempt is None:
                        attempt = {
                            "identifier": id_for_line,
                            "event_count": 0,
                            "first_dt": line_timestamp,
                            "last_dt": line_timestamp,
                            "first_timestamp": line_timestamp_text,
                            "last_timestamp": line_timestamp_text,
                            "srv_values": set(),
                            "is_srv": False,
                            "lines": [],
                        }
                        attempt_index[id_for_line] = attempt

                    attempt["event_count"] += 1
                    attempt["lines"].append(
                        {
                            "path": log_path,
                            "line_number": line_number,
                            "line": line,
                        }
                    )

                    qname_match = qname_srv_pattern.search(line)
                    if qname_match:
                        attempt["is_srv"] = True
                        attempt["srv_values"].add(qname_match.group(1).strip())
                    elif srv_signal_pattern.search(line):
                        attempt["is_srv"] = True

                    if line_timestamp is not None:
                        if attempt["first_dt"] is None or line_timestamp < attempt["first_dt"]:
                            attempt["first_dt"] = line_timestamp
                            attempt["first_timestamp"] = line_timestamp_text
                        if attempt["last_dt"] is None or line_timestamp > attempt["last_dt"]:
                            attempt["last_dt"] = line_timestamp
                            attempt["last_timestamp"] = line_timestamp_text

                    # The standalone closing brace ends the dns_packet block.
                    if in_packet and not handler_match and line.strip() == "}":
                        in_packet = False
        except OSError:
            continue

    attempts = []
    for identifier, item in attempt_index.items():
        if not item.get("is_srv"):
            continue

        # Apply the optional timeframe window at the attempt level.
        if timeframe_start and (item["last_dt"] is None or item["last_dt"] < timeframe_start):
            continue
        if timeframe_end and (item["first_dt"] is None or item["first_dt"] > timeframe_end):
            continue

        attempts.append(
            {
                "identifier": identifier,
                "event_count": item["event_count"],
                "timeframe_start": item["first_timestamp"] or "Unknown",
                "timeframe_end": item["last_timestamp"] or "Unknown",
                "srv_values": sorted(value for value in item["srv_values"] if value),
                "trace_line_count": len(item["lines"]),
                "lines": item["lines"],
                "first_dt": item["first_dt"],
            }
        )

    attempts.sort(
        key=lambda entry: (
            entry["first_dt"] is None,
            entry["first_dt"] or datetime.max,
            entry["identifier"],
        )
    )

    for entry in attempts:
        entry.pop("first_dt", None)

    return attempts


def find_spa_srv_flow_attempts(root_dir, srv_filter_value, timeframe_start=None, timeframe_end=None):
    normalized_filter = str(srv_filter_value or "").strip().lower()
    if not normalized_filter:
        return []

    timestamp_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")

    # Discovery mode: when the user does not know the exact SRV record, entering the
    # DNS SRV record type filter (type=33) lists every SRV flow found in the logs with
    # its real record name.
    if re.fullmatch(r"type\s*=?\s*33(\s+srv)?", normalized_filter):
        return _discover_all_srv_flow_attempts(
            zta_log_paths,
            timestamp_pattern,
            timeframe_start=timeframe_start,
            timeframe_end=timeframe_end,
        )

    attempt_index = {}

    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    lowered_line = line.lower()
                    if normalized_filter not in lowered_line:
                        continue

                    identifier = extract_srv_attempt_identifier(line)
                    if not identifier:
                        continue

                    timestamp_match = timestamp_pattern.match(line)
                    line_timestamp_text = timestamp_match.group(1) if timestamp_match else ""
                    line_timestamp = parse_log_timestamp(line_timestamp_text) if line_timestamp_text else None

                    if timeframe_start and (line_timestamp is None or line_timestamp < timeframe_start):
                        continue
                    if timeframe_end and (line_timestamp is None or line_timestamp > timeframe_end):
                        continue

                    if identifier not in attempt_index:
                        attempt_index[identifier] = {
                            "identifier": identifier,
                            "event_count": 0,
                            "first_dt": line_timestamp,
                            "last_dt": line_timestamp,
                            "first_timestamp": line_timestamp_text,
                            "last_timestamp": line_timestamp_text,
                            "srv_values": set(),
                            "lines": [],
                        }

                    attempt = attempt_index[identifier]
                    attempt["event_count"] += 1
                    attempt["srv_values"].add(str(srv_filter_value).strip())
                    attempt["lines"].append(
                        {
                            "path": log_path,
                            "line_number": line_number,
                            "line": line,
                        }
                    )

                    if line_timestamp is not None:
                        if attempt["first_dt"] is None or line_timestamp < attempt["first_dt"]:
                            attempt["first_dt"] = line_timestamp
                            attempt["first_timestamp"] = line_timestamp_text
                        if attempt["last_dt"] is None or line_timestamp > attempt["last_dt"]:
                            attempt["last_dt"] = line_timestamp
                            attempt["last_timestamp"] = line_timestamp_text

        except OSError:
            continue

    attempts = []
    for identifier, item in attempt_index.items():
        attempts.append(
            {
                "identifier": identifier,
                "event_count": item["event_count"],
                "timeframe_start": item["first_timestamp"] or "Unknown",
                "timeframe_end": item["last_timestamp"] or "Unknown",
                "srv_values": sorted(value for value in item["srv_values"] if value),
                "trace_line_count": len(item["lines"]),
                "lines": item["lines"],
                "first_dt": item["first_dt"],
            }
        )

    attempts.sort(
        key=lambda entry: (
            entry["first_dt"] is None,
            entry["first_dt"] or datetime.max,
            entry["identifier"],
        )
    )

    for entry in attempts:
        entry.pop("first_dt", None)

    return attempts


def find_zta_log_lines_by_identifier(
    root_dir,
    identifier,
    timeframe_start=None,
    timeframe_end=None,
):
    normalized_identifier = str(identifier or "").strip()
    if not normalized_identifier:
        return []

    identifier_pattern = re.compile(rf"\b{re.escape(normalized_identifier)}\b", re.IGNORECASE)
    timestamp_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
    matched_lines = []

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                capture_continuation = False
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")

                    if capture_continuation:
                        if timestamp_pattern.match(line):
                            capture_continuation = False
                        else:
                            matched_lines.append(
                                {
                                    "path": log_path,
                                    "line_number": line_number,
                                    "line": line,
                                }
                            )
                            continue

                    if not identifier_pattern.search(line):
                        continue

                    timestamp_match = timestamp_pattern.match(line)
                    line_timestamp = parse_log_timestamp(timestamp_match.group(1)) if timestamp_match else None
                    if timeframe_start and (line_timestamp is None or line_timestamp < timeframe_start):
                        continue
                    if timeframe_end and (line_timestamp is None or line_timestamp > timeframe_end):
                        continue

                    matched_lines.append(
                        {
                            "path": log_path,
                            "line_number": line_number,
                            "line": line,
                        }
                    )
                    capture_continuation = True
        except OSError:
            continue

    return matched_lines


def find_server_connectivity_error_lines(root_dir, max_matches=120):
    issue_patterns = [
        re.compile(r"server\s+connectivity", re.IGNORECASE),
        re.compile(r"connect(?:ion)?\s+(?:failed|refused|error)", re.IGNORECASE),
        re.compile(r"unable\s+to\s+connect", re.IGNORECASE),
        re.compile(r"timed?\s*out|timeout", re.IGNORECASE),
        re.compile(r"network\s+unreachable|host\s+unreachable", re.IGNORECASE),
        re.compile(r"dns\s+(?:resolution|resolve).*(?:failed|error)", re.IGNORECASE),
        re.compile(r"tls\s+handshake\s+failed", re.IGNORECASE),
        re.compile(r"socket\s+error", re.IGNORECASE),
    ]
    timestamp_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)"
    )

    matches = []
    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    if not any(pattern.search(line) for pattern in issue_patterns):
                        continue

                    timestamp_match = timestamp_pattern.match(line)
                    timestamp_text = timestamp_match.group(1) if timestamp_match else ""
                    matches.append(
                        {
                            "path": log_path,
                            "line_number": line_number,
                            "line": line,
                            "timestamp": parse_log_timestamp(timestamp_text),
                            "timestamp_text": timestamp_text or "Unknown",
                        }
                    )
        except OSError:
            continue

    matches.sort(
        key=lambda entry: (
            entry["timestamp"] is None,
            entry["timestamp"] or datetime.max,
            entry["path"],
            entry["line_number"],
        )
    )
    if len(matches) > max_matches:
        matches = matches[-max_matches:]
    return matches


def collect_server_connectivity_timeout_context(root_dir, max_matches_per_group=120):
    timestamp_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)"
    )
    flow_id_pattern = re.compile(r"\b([0-9A-F]{8})\b")

    request_timeout_pattern = re.compile(r"request\s+timeout", re.IGNORECASE)
    closing_reason_pattern = re.compile(
        r"closing\s+due\s+to\s+error\s+reason:\s*request_timeout\s+error:\s*RequestTimedOut",
        re.IGNORECASE,
    )
    close_status_pattern = re.compile(r"closeStatus\s*=\s*RequestTimedOut", re.IGNORECASE)
    update_main_ui_pattern = re.compile(
        r"updateMainUi\(\).*server\s+connectivity\s+error",
        re.IGNORECASE,
    )
    update_tile_status_pattern = re.compile(
        r"updateTileStatusStrings\(\).*server\s+connectivity\s+error",
        re.IGNORECASE,
    )
    transport_network_change_pattern = re.compile(
        r"ZtnaTransportManager::handleNetworkChange\(\).*handling\s+network\s+change",
        re.IGNORECASE,
    )
    server_unreachable_pattern = re.compile(
        r"request\s+error:\s*'ServerUnreachable'",
        re.IGNORECASE,
    )
    request_msg_msft_pattern = re.compile(
        r"requestMsg:\s*'method=GET\s+url=\[http://www\.msftconnecttest\.com/connecttest\.txt\]",
        re.IGNORECASE,
    )
    msft_connecttest_url_pattern = re.compile(
        r"msftconnecttest\.com/connecttest\.txt",
        re.IGNORECASE,
    )

    def build_entry(path, line_number, line, timestamp_value, timestamp_text):
        flow_match = flow_id_pattern.search(line)
        return {
            "path": path,
            "line_number": line_number,
            "line": line,
            "timestamp": timestamp_value,
            "timestamp_text": timestamp_text or "Unknown",
            "flow_id": flow_match.group(1) if flow_match else "",
        }

    grouped = {
        "request_timeout_flows": [],
        "closing_reason": [],
        "close_status": [],
        "update_main_ui_server_error": [],
        "update_tile_status_server_error": [],
        "transport_handle_network_change": [],
        "server_unreachable_connecttest": [],
    }

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    for log_path in zta_log_paths:
        previous_timestamp = None
        previous_timestamp_text = ""
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                pending_server_unreachable_entry = None
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    timestamp_match = timestamp_pattern.match(line)
                    if timestamp_match:
                        previous_timestamp_text = timestamp_match.group(1)
                        previous_timestamp = parse_log_timestamp(previous_timestamp_text)
                        pending_server_unreachable_entry = None

                    effective_timestamp = previous_timestamp
                    effective_timestamp_text = previous_timestamp_text or ""

                    if request_timeout_pattern.search(line):
                        grouped["request_timeout_flows"].append(
                            build_entry(log_path, line_number, line, effective_timestamp, effective_timestamp_text)
                        )
                    if closing_reason_pattern.search(line):
                        grouped["closing_reason"].append(
                            build_entry(log_path, line_number, line, effective_timestamp, effective_timestamp_text)
                        )
                    if close_status_pattern.search(line):
                        grouped["close_status"].append(
                            build_entry(log_path, line_number, line, effective_timestamp, effective_timestamp_text)
                        )

                    if update_main_ui_pattern.search(line):
                        grouped["update_main_ui_server_error"].append(
                            build_entry(log_path, line_number, line, effective_timestamp, effective_timestamp_text)
                        )

                    if update_tile_status_pattern.search(line):
                        grouped["update_tile_status_server_error"].append(
                            build_entry(log_path, line_number, line, effective_timestamp, effective_timestamp_text)
                        )

                    if transport_network_change_pattern.search(line):
                        grouped["transport_handle_network_change"].append(
                            build_entry(log_path, line_number, line, effective_timestamp, effective_timestamp_text)
                        )

                    if server_unreachable_pattern.search(line):
                        pending_server_unreachable_entry = build_entry(
                            log_path,
                            line_number,
                            line,
                            effective_timestamp,
                            effective_timestamp_text,
                        )
                        if request_msg_msft_pattern.search(line) or msft_connecttest_url_pattern.search(line):
                            grouped["server_unreachable_connecttest"].append(pending_server_unreachable_entry)
                            pending_server_unreachable_entry = None
                        continue

                    if pending_server_unreachable_entry and (
                        request_msg_msft_pattern.search(line)
                        or msft_connecttest_url_pattern.search(line)
                    ):
                        pending_server_unreachable_entry["line"] = (
                            pending_server_unreachable_entry["line"] + " | " + line.strip()
                        )
                        grouped["server_unreachable_connecttest"].append(pending_server_unreachable_entry)
                        pending_server_unreachable_entry = None
        except OSError:
            continue

    for key in grouped:
        grouped[key].sort(
            key=lambda entry: (
                entry["timestamp"] is None,
                entry["timestamp"] or datetime.max,
                entry["path"],
                entry["line_number"],
            )
        )
        if len(grouped[key]) > max_matches_per_group:
            grouped[key] = grouped[key][-max_matches_per_group:]

    unique_timeout_flows = sorted(
        {
            entry["flow_id"]
            for entry in grouped["request_timeout_flows"]
            if entry.get("flow_id")
        }
    )

    all_entries = (
        grouped["request_timeout_flows"]
        + grouped["closing_reason"]
        + grouped["close_status"]
    )
    anchor_timestamps = [entry.get("timestamp") for entry in all_entries if entry.get("timestamp")]
    timeframe_start = min(anchor_timestamps) if anchor_timestamps else None
    timeframe_end = max(anchor_timestamps) if anchor_timestamps else None

    return {
        "request_timeout_flows": grouped["request_timeout_flows"],
        "closing_reason": grouped["closing_reason"],
        "close_status": grouped["close_status"],
        "update_main_ui_server_error": grouped["update_main_ui_server_error"],
        "update_tile_status_server_error": grouped["update_tile_status_server_error"],
        "transport_handle_network_change": grouped["transport_handle_network_change"],
        "server_unreachable_connecttest": grouped["server_unreachable_connecttest"],
        "unique_timeout_flows": unique_timeout_flows,
        "anchor_timestamps": anchor_timestamps,
        "timeframe_start": timeframe_start,
        "timeframe_end": timeframe_end,
    }


def collect_proxy_connectivity_transition_context(root_dir):
    timestamp_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)"
    )
    proxy_ok_pattern = re.compile(r"proxy\s+connectivity\s*:\s*ok\b", re.IGNORECASE)
    proxy_unreachable_pattern = re.compile(
        r"proxy\s+connectivity\s*:\s*unreachable\b",
        re.IGNORECASE,
    )

    best_candidate = None
    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")

    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                line_records = []
                ok_indices = []
                unreachable_indices = []
                previous_timestamp = None
                previous_timestamp_text = ""

                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    timestamp_match = timestamp_pattern.match(line)
                    if timestamp_match:
                        previous_timestamp_text = timestamp_match.group(1)
                        previous_timestamp = parse_log_timestamp(previous_timestamp_text)

                    line_records.append(
                        {
                            "path": log_path,
                            "line_number": line_number,
                            "line": line,
                            "timestamp": previous_timestamp,
                            "timestamp_text": previous_timestamp_text or "Unknown",
                        }
                    )

                    if proxy_ok_pattern.search(line):
                        ok_indices.append(len(line_records) - 1)
                    if proxy_unreachable_pattern.search(line):
                        unreachable_indices.append(len(line_records) - 1)

                if not ok_indices or not unreachable_indices:
                    continue

                for ok_idx in reversed(ok_indices):
                    first_unreachable_idx = next(
                        (idx for idx in unreachable_indices if idx > ok_idx),
                        None,
                    )
                    if first_unreachable_idx is None:
                        continue

                    ok_entry = line_records[ok_idx]
                    unreachable_entry = line_records[first_unreachable_idx]
                    candidate = {
                        "ok_entry": ok_entry,
                        "unreachable_entry": unreachable_entry,
                        "lines": line_records[ok_idx:first_unreachable_idx + 1],
                        "source_file": log_path,
                    }
                    if best_candidate is None:
                        best_candidate = candidate
                        break

                    best_ok_entry = best_candidate["ok_entry"]
                    current_ok_timestamp = ok_entry.get("timestamp")
                    best_ok_timestamp = best_ok_entry.get("timestamp")

                    if current_ok_timestamp and best_ok_timestamp:
                        if current_ok_timestamp > best_ok_timestamp:
                            best_candidate = candidate
                    elif current_ok_timestamp and not best_ok_timestamp:
                        best_candidate = candidate
                    elif not current_ok_timestamp and not best_ok_timestamp:
                        if ok_entry["line_number"] > best_ok_entry["line_number"]:
                            best_candidate = candidate
                    break
        except OSError:
            continue

    if not best_candidate:
        return {
            "found": False,
            "ok_entry": None,
            "unreachable_entry": None,
            "lines": [],
        }

    return {
        "found": True,
        "ok_entry": best_candidate["ok_entry"],
        "unreachable_entry": best_candidate["unreachable_entry"],
        "lines": best_candidate["lines"],
    }


def analyze_trusted_network_detection_runtime(root_dir):
    """Parse csc_zta_agent ZTA logs to determine the actual runtime Trusted
    Network Detection (TND) state per proxy configuration.

    Reproduces the detection flow documented in the Cisco "From DART Bundle -
    ZTA Logs" verification steps:
      * "TND will connect ProxyConfig '<id>' (no rules)"           -> no TND rules for that proxy
      * "TND will disconnect ProxyConfig '<label>' due to condition:
         on_network: <fingerprint> action=Disconnect"              -> trusted network matched
      * "ProxyConfig '<label>' is disconnecting due to: InactiveTnd" -> proxy paused by TND
      * "broadcasting network fingerprint status: Fingerprint: <fp> Interfaces: <iface>" -> fingerprint matched
      * "NetworkChangeService::Start() Initial network snapshot: <iface>: subnets=... dns_servers=..." -> network context
      * "closeObsoleteAppFlows() ... proxyConfigId=<id> ... matchRuleType=DNS" -> app flow torn down by TND
    """
    flow_definitions = {
        "SPA": {"proxy_config_id": "default_spa_config", "proxy_config_label": "Secure Private Access"},
        "SIA": {"proxy_config_id": "default_tia_config", "proxy_config_label": "Secure Internet Access"},
    }

    def match_flow(proxy_text):
        text = str(proxy_text or "").strip().lower()
        if not text:
            return None
        if "default_spa_config" in text or "secure private access" in text:
            return "SPA"
        if "default_tia_config" in text or "secure internet access" in text:
            return "SIA"
        return None

    timestamp_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)"
    )
    connect_no_rules_pattern = re.compile(
        r"TND will connect ProxyConfig\s+['\"]?(.+?)['\"]?\s*\(\s*no rules\s*\)",
        re.IGNORECASE,
    )
    disconnect_condition_pattern = re.compile(
        r"TND will disconnect ProxyConfig\s+['\"]?(.+?)['\"]?\s+due to condition:\s*(.+?)\s*$",
        re.IGNORECASE,
    )
    inactive_tnd_pattern = re.compile(
        r"ProxyConfig\s+['\"]?(.+?)['\"]?\s+is disconnecting due to:\s*InactiveTnd\b",
        re.IGNORECASE,
    )
    fingerprint_status_pattern = re.compile(
        r"broadcasting network fingerprint status:\s*Fingerprint:\s*([0-9a-fA-F][0-9a-fA-F-]{15,})\s+Interfaces:\s*(.+?)\s*$",
        re.IGNORECASE,
    )
    snapshot_iface_pattern = re.compile(
        r"^\s*(\S+):\s+subnets=(\S+)\s+dns_servers=(\S+)\s+dns_domain=(\S+)\s+dns_suffixes=(\S+)",
        re.IGNORECASE,
    )
    close_flow_pattern = re.compile(r"closeObsoleteAppFlows\(\)", re.IGNORECASE)
    proxy_config_id_pattern = re.compile(r"proxyConfigId=(\S+)", re.IGNORECASE)
    destination_pattern = re.compile(r"destination\s+\[([^\]]+)\]:(\d+)", re.IGNORECASE)
    match_rule_type_pattern = re.compile(r"matchRuleType=(\S+)", re.IGNORECASE)
    on_network_fp_pattern = re.compile(r"on_network:\s*([0-9a-fA-F][0-9a-fA-F-]{15,})", re.IGNORECASE)
    action_pattern = re.compile(r"action=(\w+)", re.IGNORECASE)

    per_flow = {}
    for flow_key, definition in flow_definitions.items():
        per_flow[flow_key] = {
            "flow": flow_key,
            "proxy_config_id": definition["proxy_config_id"],
            "proxy_config_label": definition["proxy_config_label"],
            "runtime_found": False,
            "tnd_rules_present": None,
            "paused_by_tnd": False,
            "runtime_status": "Unknown",
            "matched_fingerprints": set(),
            "pause_conditions": set(),
            "closed_flows": [],
            "last_event_timestamp": "",
            "pause_event_timestamps": [],
        }

    network_fingerprint_events = []
    fingerprint_event_seen = set()
    network_snapshots = []
    snapshot_seen = set()
    evidence_lines = []

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")

    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                current_timestamp = ""
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    ts_match = timestamp_pattern.match(line)
                    if ts_match:
                        current_timestamp = ts_match.group(1)

                    stripped_line = line.strip()

                    def add_evidence(category):
                        evidence_lines.append(
                            {
                                "path": log_path,
                                "line_number": line_number,
                                "timestamp_text": current_timestamp or "Unknown",
                                "line": stripped_line,
                                "category": category,
                            }
                        )

                    # "TND will connect ProxyConfig '<id>' (no rules)" -> no TND rules configured.
                    no_rules_match = connect_no_rules_pattern.search(line)
                    if no_rules_match:
                        flow_key = match_flow(no_rules_match.group(1))
                        if flow_key:
                            info = per_flow[flow_key]
                            info["runtime_found"] = True
                            if info["tnd_rules_present"] is None:
                                info["tnd_rules_present"] = False
                            info["last_event_timestamp"] = current_timestamp or info["last_event_timestamp"]
                            add_evidence("no_rules")
                        continue

                    # "TND will disconnect ProxyConfig '<label>' due to condition: on_network: <fp> action=Disconnect"
                    disconnect_match = disconnect_condition_pattern.search(line)
                    if disconnect_match:
                        flow_key = match_flow(disconnect_match.group(1))
                        condition_text = disconnect_match.group(2).strip()
                        if flow_key:
                            info = per_flow[flow_key]
                            info["runtime_found"] = True
                            info["paused_by_tnd"] = True
                            info["tnd_rules_present"] = True
                            fp_match = on_network_fp_pattern.search(condition_text)
                            action_match = action_pattern.search(condition_text)
                            fingerprint_ref = fp_match.group(1) if fp_match else ""
                            action_value = action_match.group(1) if action_match else ""
                            if fingerprint_ref:
                                info["matched_fingerprints"].add(fingerprint_ref)
                            condition_label = "on_network"
                            if fingerprint_ref:
                                condition_label += f": {fingerprint_ref}"
                            if action_value:
                                condition_label += f" action={action_value}"
                            info["pause_conditions"].add(condition_label)
                            info["last_event_timestamp"] = current_timestamp or info["last_event_timestamp"]
                            if current_timestamp:
                                info["pause_event_timestamps"].append(current_timestamp)
                            add_evidence("disconnect_condition")
                        continue

                    # "ProxyConfig '<label>' is disconnecting due to: InactiveTnd" -> paused by TND.
                    inactive_match = inactive_tnd_pattern.search(line)
                    if inactive_match:
                        flow_key = match_flow(inactive_match.group(1))
                        if flow_key:
                            info = per_flow[flow_key]
                            info["runtime_found"] = True
                            info["paused_by_tnd"] = True
                            info["tnd_rules_present"] = True
                            info["last_event_timestamp"] = current_timestamp or info["last_event_timestamp"]
                            if current_timestamp:
                                info["pause_event_timestamps"].append(current_timestamp)
                            add_evidence("inactive_tnd")
                        continue

                    # "broadcasting network fingerprint status: Fingerprint: <fp> Interfaces: <iface>"
                    fingerprint_match = fingerprint_status_pattern.search(line)
                    if fingerprint_match:
                        fingerprint_ref = fingerprint_match.group(1).strip()
                        interfaces = fingerprint_match.group(2).strip()
                        event_key = (fingerprint_ref.lower(), interfaces.lower())
                        if event_key not in fingerprint_event_seen:
                            fingerprint_event_seen.add(event_key)
                            network_fingerprint_events.append(
                                {
                                    "fingerprint": fingerprint_ref,
                                    "interfaces": interfaces,
                                    "timestamp_text": current_timestamp or "Unknown",
                                }
                            )
                        add_evidence("fingerprint_matched")
                        continue

                    # "Initial network snapshot: <iface>: subnets=... dns_servers=... dns_domain=... dns_suffixes=..."
                    snapshot_match = snapshot_iface_pattern.search(line)
                    if snapshot_match:
                        iface, subnets, dns_servers, dns_domain, dns_suffixes = snapshot_match.groups()
                        snapshot_key = (iface.lower(), subnets.lower(), dns_servers.lower())
                        if snapshot_key not in snapshot_seen:
                            snapshot_seen.add(snapshot_key)
                            network_snapshots.append(
                                {
                                    "interface": iface,
                                    "subnets": subnets,
                                    "dns_servers": dns_servers,
                                    "dns_domain": dns_domain,
                                    "dns_suffixes": dns_suffixes,
                                    "timestamp_text": current_timestamp or "Unknown",
                                }
                            )
                        add_evidence("network_snapshot")
                        continue

                    # "closeObsoleteAppFlows() ... proxyConfigId=<id> ... matchRuleType=DNS" -> flow torn down.
                    if close_flow_pattern.search(line):
                        proxy_id_match = proxy_config_id_pattern.search(line)
                        flow_key = match_flow(proxy_id_match.group(1)) if proxy_id_match else None
                        if flow_key:
                            info = per_flow[flow_key]
                            info["runtime_found"] = True
                            destination_match = destination_pattern.search(line)
                            rule_match = match_rule_type_pattern.search(line)
                            destination = (
                                f"{destination_match.group(1)}:{destination_match.group(2)}"
                                if destination_match
                                else ""
                            )
                            info["closed_flows"].append(
                                {
                                    "destination": destination,
                                    "match_rule_type": rule_match.group(1) if rule_match else "",
                                    "timestamp_text": current_timestamp or "Unknown",
                                }
                            )
                            add_evidence("closed_flow")
                        continue
        except OSError:
            continue

    for info in per_flow.values():
        pause_times = sorted(info.get("pause_event_timestamps", []))
        info["pause_start"] = pause_times[0] if pause_times else ""
        info["pause_end"] = pause_times[-1] if pause_times else ""
        if info["paused_by_tnd"]:
            info["runtime_status"] = "Paused by TND"
        elif info["tnd_rules_present"] is False:
            info["runtime_status"] = "Active (no TND rules)"
        elif info["tnd_rules_present"] is True:
            info["runtime_status"] = "Configured (not on trusted network)"
        else:
            info["runtime_status"] = "Unknown"

    return {
        "found": (
            any(info["runtime_found"] for info in per_flow.values())
            or bool(network_fingerprint_events)
            or bool(network_snapshots)
        ),
        "flows": per_flow,
        "network_fingerprint_events": network_fingerprint_events,
        "network_snapshots": network_snapshots,
        "evidence": evidence_lines,
    }


def extract_user_pause_config_entries(json_path):
    """Return the structured user_pause_configs entries from a cached ZTA
    config JSON, e.g.:

        "user_pause_configs":[
            {"id":"spa_pause_config","label":"Pause SPA","resume_timeout":1800},
            {"id":"tia_pause_config","label":"Pause TIA","resume_timeout":1800}
        ]

    Each returned dict keeps id / label / resume_timeout so the caller can map
    the entry to its SPA / SIA proxy config.
    """

    def normalize_key_tokens(key_name):
        key_text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key_name))
        key_text = key_text.replace("_", " ").replace("-", " ").lower()
        return re.sub(r"\s+", " ", key_text).strip()

    def key_matches_user_pause_configs(key_name):
        normalized = normalize_key_tokens(key_name)
        return "user" in normalized and "pause" in normalized and "config" in normalized

    with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
        payload = json.load(handle)

    entries = []
    seen = set()

    def add_entry(node):
        if not isinstance(node, dict):
            return
        identifier = str(node.get("id", "")).strip()
        label = str(node.get("label", "")).strip()
        resume_timeout = node.get("resume_timeout", node.get("resumeTimeout"))
        dedupe_key = (identifier, label, str(resume_timeout))
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        entries.append(
            {
                "id": identifier,
                "label": label,
                "resume_timeout": resume_timeout,
            }
        )

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key_matches_user_pause_configs(key):
                    if isinstance(value, list):
                        for item in value:
                            add_entry(item)
                    elif isinstance(value, dict):
                        add_entry(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return entries


def analyze_user_pause_runtime(root_dir):
    """Parse csc_zta_api / csc_zta_agent ZTA logs to determine the actual
    runtime User Pause state per proxy configuration.

    Reproduces the Cisco "From DART Bundle - ZTA Logs" user-pause verification
    flow:
      * "ZtnaApiImpl::InitiatePause() Initiating Pause"                         -> user requested a pause
      * "handlePauseRequest() Requesting pause for proxy config: <id>"          -> pause requested for a proxy config
      * "UserPauseManager::PauseProxyConfig() Pausing proxy config '<id>' with
         max duration '<N>' seconds"                                           -> pause applied, resume timeout
      * "Pause request completed for enrollment: '<uuid>' proxy config: '<id>'
         error: '<err>' context: '<ctx>'"                                      -> pause result
      * "collectProxyConfigPauseReasons() User pause will disconnect ProxyConfig
         '<label>'"                                                            -> proxy will disconnect due to user pause
      * "ProxyConfig '<label>' is disconnecting due to: InactiveUserPaused"     -> proxy paused by the user
    """
    flow_definitions = {
        "SPA": {"proxy_config_id": "default_spa_config", "proxy_config_label": "Secure Private Access"},
        "SIA": {"proxy_config_id": "default_tia_config", "proxy_config_label": "Secure Internet Access"},
    }

    def match_flow(proxy_text):
        text = str(proxy_text or "").strip().lower()
        if not text:
            return None
        if "default_spa_config" in text or "secure private access" in text or "spa" in text:
            return "SPA"
        if (
            "default_tia_config" in text
            or "secure internet access" in text
            or "tia" in text
            or "sia" in text
        ):
            return "SIA"
        return None

    timestamp_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)"
    )
    initiate_pattern = re.compile(r"InitiatePause\(\)\s+Initiating Pause", re.IGNORECASE)
    request_pattern = re.compile(
        r"handlePauseRequest\(\)\s+Requesting pause for proxy config:\s*(\S+)",
        re.IGNORECASE,
    )
    pause_proxy_pattern = re.compile(
        r"PauseProxyConfig\(\)\s+Pausing proxy config\s+['\"]([^'\"]+)['\"]\s+with max duration\s+['\"]?(\d+)['\"]?\s+seconds",
        re.IGNORECASE,
    )
    completed_pattern = re.compile(
        r"Pause request completed for enrollment:\s*['\"]?([^'\"]*)['\"]?\s+proxy config:\s*['\"]?([^'\"]*)['\"]?\s+error:\s*['\"]?([^'\"]*)['\"]?",
        re.IGNORECASE,
    )
    disconnect_reason_pattern = re.compile(
        r"collectProxyConfigPauseReasons\(\)\s+User pause will disconnect ProxyConfig\s+['\"]?(.+?)['\"]?\s*$",
        re.IGNORECASE,
    )
    inactive_paused_pattern = re.compile(
        r"ProxyConfig\s+['\"]?(.+?)['\"]?\s+is disconnecting due to:\s*InactiveUserPaused\b",
        re.IGNORECASE,
    )

    per_flow = {}
    for flow_key, definition in flow_definitions.items():
        per_flow[flow_key] = {
            "flow": flow_key,
            "proxy_config_id": definition["proxy_config_id"],
            "proxy_config_label": definition["proxy_config_label"],
            "runtime_found": False,
            "pause_requested": False,
            "pause_applied": False,
            "paused_by_user": False,
            "will_disconnect": False,
            "pause_result": "",
            "enrollment_id": "",
            "max_duration_seconds": None,
            "runtime_status": "Unknown",
            "pause_event_timestamps": [],
        }

    pause_initiated = False
    evidence_lines = []

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")

    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                current_timestamp = ""
                for line_number, raw_line in enumerate(handle, start=1):
                    line = raw_line.rstrip("\n")
                    ts_match = timestamp_pattern.match(line)
                    if ts_match:
                        current_timestamp = ts_match.group(1)
                    stripped_line = line.strip()

                    def add_evidence(category):
                        evidence_lines.append(
                            {
                                "path": log_path,
                                "line_number": line_number,
                                "timestamp_text": current_timestamp or "Unknown",
                                "line": stripped_line,
                                "category": category,
                            }
                        )

                    if initiate_pattern.search(line):
                        pause_initiated = True
                        add_evidence("initiate_pause")
                        continue

                    request_match = request_pattern.search(line)
                    if request_match:
                        flow_key = match_flow(request_match.group(1))
                        if flow_key:
                            info = per_flow[flow_key]
                            info["runtime_found"] = True
                            info["pause_requested"] = True
                            info["last_event_timestamp"] = current_timestamp
                            if current_timestamp:
                                info["pause_event_timestamps"].append(current_timestamp)
                            add_evidence("pause_requested")
                        continue

                    pause_proxy_match = pause_proxy_pattern.search(line)
                    if pause_proxy_match:
                        flow_key = match_flow(pause_proxy_match.group(1))
                        if flow_key:
                            info = per_flow[flow_key]
                            info["runtime_found"] = True
                            info["pause_applied"] = True
                            info["paused_by_user"] = True
                            try:
                                info["max_duration_seconds"] = int(pause_proxy_match.group(2))
                            except (TypeError, ValueError):
                                pass
                            if current_timestamp:
                                info["pause_event_timestamps"].append(current_timestamp)
                            add_evidence("pause_applied")
                        continue

                    completed_match = completed_pattern.search(line)
                    if completed_match:
                        enrollment_id = completed_match.group(1).strip()
                        proxy_config = completed_match.group(2).strip()
                        error_text = completed_match.group(3).strip()
                        flow_key = match_flow(proxy_config)
                        if flow_key:
                            info = per_flow[flow_key]
                            info["runtime_found"] = True
                            info["pause_result"] = error_text
                            if enrollment_id:
                                info["enrollment_id"] = enrollment_id
                            if error_text.lower() == "success":
                                info["paused_by_user"] = True
                            if current_timestamp:
                                info["pause_event_timestamps"].append(current_timestamp)
                            add_evidence("pause_completed")
                        continue

                    disconnect_match = disconnect_reason_pattern.search(line)
                    if disconnect_match:
                        flow_key = match_flow(disconnect_match.group(1))
                        if flow_key:
                            info = per_flow[flow_key]
                            info["runtime_found"] = True
                            info["will_disconnect"] = True
                            info["paused_by_user"] = True
                            if current_timestamp:
                                info["pause_event_timestamps"].append(current_timestamp)
                            add_evidence("will_disconnect")
                        continue

                    inactive_match = inactive_paused_pattern.search(line)
                    if inactive_match:
                        flow_key = match_flow(inactive_match.group(1))
                        if flow_key:
                            info = per_flow[flow_key]
                            info["runtime_found"] = True
                            info["paused_by_user"] = True
                            if current_timestamp:
                                info["pause_event_timestamps"].append(current_timestamp)
                            add_evidence("inactive_user_paused")
                        continue
        except OSError:
            continue

    for info in per_flow.values():
        pause_times = sorted(info.get("pause_event_timestamps", []))
        info["pause_start"] = pause_times[0] if pause_times else ""
        info["pause_end"] = pause_times[-1] if pause_times else ""
        if info["paused_by_user"]:
            info["runtime_status"] = "Paused by User"
        elif info["pause_requested"]:
            info["runtime_status"] = "Pause Requested"
        else:
            info["runtime_status"] = "Not Paused"

    return {
        "found": any(info["runtime_found"] for info in per_flow.values()),
        "pause_initiated": pause_initiated,
        "flows": per_flow,
        "evidence": evidence_lines,
    }


def collect_configuration_sync_error_context(root_dir, max_matches=500):
    timestamp_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)"
    )
    init_sync_pattern = re.compile(r"ConfigSync::InitSync\s*\(\)", re.IGNORECASE)
    on_config_sync_stats_pattern = re.compile(r"ZtnaClientManager::OnConfigSyncStats", re.IGNORECASE)
    stats_header_pattern = re.compile(r"Notified\s+of\s+config\s+sync\s+stats\s*:", re.IGNORECASE)
    enrollment_bracket_pattern = re.compile(r"Enrollment\[([^\]]+)\]")
    key_value_pattern = re.compile(r"^([^:]+):\s*(.*)$")
    configsync_cpp_pattern = re.compile(r"ConfigSync\.cpp", re.IGNORECASE)
    exclude_cert_alias_pattern = re.compile(
        r"ConfigSync\.cpp:194\s+ConfigSync::InitSync\(\)\s+setting\s+cert\s+alias",
        re.IGNORECASE,
    )
    exclude_using_identity_pattern = re.compile(
        r"ConfigSync::InitSync\(\)\s+using\s+identity",
        re.IGNORECASE,
    )
    exclude_initiated_post_request_pattern = re.compile(
        r"ConfigSync::InitSync\(\)\s+Initiated\s+POST\s+HTTP\s+request",
        re.IGNORECASE,
    )
    configsync_scope_pattern = re.compile(r"ConfigSync::|ConfigSync\.cpp", re.IGNORECASE)
    configsync_url_status_pattern = re.compile(r"\bconfigSyncUrl=", re.IGNORECASE)
    configsync_error_pattern = re.compile(
        r"\b(error|failed|failure|exception|timeout|timed\s*out|unreachable|forbidden|unauthorized)\b",
        re.IGNORECASE,
    )
    status_code_pattern = re.compile(r"(?:http_status|statusCode|status)\s*[:=]\s*([0-9]{3})", re.IGNORECASE)

    def extract_inline_config_value(line_text, key_name):
        pattern = re.compile(
            rf"\b{re.escape(key_name)}=([^=]+?)(?=\s+[A-Za-z][A-Za-z0-9_]*=|$)",
            re.IGNORECASE,
        )
        match = pattern.search(str(line_text or ""))
        return match.group(1).strip() if match else ""

    configsync_entries = []
    configsync_error_entries = []
    stats_notifications = []
    schedule_snapshots = []
    stats_counter = Counter()
    unique_enrollment_ids = set()

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")

    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                all_lines = handle.readlines()
        except OSError:
            continue

        previous_timestamp = None
        previous_timestamp_text = ""
        line_number = 0

        while line_number < len(all_lines):
            raw_line = all_lines[line_number]
            line = raw_line.rstrip("\n")
            absolute_line_number = line_number + 1

            timestamp_match = timestamp_pattern.match(line)
            if timestamp_match:
                previous_timestamp_text = timestamp_match.group(1)
                previous_timestamp = parse_log_timestamp(previous_timestamp_text)

            lowered_line = line.lower()

            if (
                configsync_cpp_pattern.search(line)
                and not exclude_cert_alias_pattern.search(line)
                and not exclude_using_identity_pattern.search(line)
            ):
                entry = {
                    "path": log_path,
                    "line_number": absolute_line_number,
                    "line": line,
                    "timestamp": previous_timestamp,
                    "timestamp_text": previous_timestamp_text or "Unknown",
                }
                configsync_entries.append(entry)

                if "initsync()" in lowered_line and "sent config sync request" in lowered_line:
                    stats_counter["sent_requests"] += 1

                for enrollment_match in enrollment_bracket_pattern.findall(line):
                    normalized_id = str(enrollment_match).strip()
                    if normalized_id:
                        unique_enrollment_ids.add(normalized_id)

            if configsync_url_status_pattern.search(line):
                interval_minutes_text = extract_inline_config_value(line, "configSyncIntervalMin")
                last_success_text = extract_inline_config_value(line, "lastSyncSuccessTime")
                last_response_text = extract_inline_config_value(line, "lastSyncResponseTime")
                fail_count_text = extract_inline_config_value(line, "failCntSinceLastSyncSuccess")

                if any(
                    (
                        interval_minutes_text,
                        last_success_text,
                        last_response_text,
                        fail_count_text,
                    )
                ):
                    schedule_snapshot = {
                        "path": log_path,
                        "line_number": absolute_line_number,
                        "timestamp": previous_timestamp,
                        "timestamp_text": previous_timestamp_text or "Unknown",
                        "fail_count_since_last_success": fail_count_text,
                        "last_sync_attempt_time": last_success_text,
                        "last_sync_response_time": last_response_text,
                        "now_tp": "",
                        "interval_seconds": "",
                        "next_sync_tp": "",
                    }

                    if interval_minutes_text.isdigit():
                        interval_seconds = int(interval_minutes_text) * 60
                        schedule_snapshot["interval_seconds"] = str(interval_seconds)

                        # Derive next sync estimate when response time is available in text form.
                        if last_response_text and last_response_text.upper() != "N/A":
                            try:
                                response_dt = datetime.strptime(last_response_text, "%a %b %d %H:%M:%S %Y")
                                next_sync_dt = response_dt + timedelta(seconds=interval_seconds)
                                schedule_snapshot["next_sync_tp"] = next_sync_dt.strftime("%a %b %d %H:%M:%S %Y")
                            except ValueError:
                                pass
                    elif interval_minutes_text:
                        schedule_snapshot["interval_seconds"] = interval_minutes_text

                    schedule_snapshots.append(schedule_snapshot)

            if "client already has the latest config" in lowered_line:
                stats_counter["already_latest"] += 1
            if "config sync was successful" in lowered_line:
                stats_counter["sync_success"] += 1

            if configsync_scope_pattern.search(line):
                status_code_match = status_code_pattern.search(line)
                status_is_error = False
                if status_code_match:
                    try:
                        status_is_error = int(status_code_match.group(1)) >= 400
                    except ValueError:
                        status_is_error = False

                explicit_error = bool(configsync_error_pattern.search(line))
                benign_line = (
                    "config sync was successful" in lowered_line
                    or "client already has the latest config" in lowered_line
                    or "received sync response with http_status:304" in lowered_line
                )

                if (explicit_error or status_is_error) and not benign_line:
                    configsync_error_entries.append(
                        {
                            "path": log_path,
                            "line_number": absolute_line_number,
                            "line": line,
                            "timestamp": previous_timestamp,
                            "timestamp_text": previous_timestamp_text or "Unknown",
                        }
                    )

            if "scheduleconfigsync()" in line.lower():
                stats_counter["schedule_calls"] += 1
                schedule_snapshot = {
                    "path": log_path,
                    "line_number": absolute_line_number,
                    "timestamp": previous_timestamp,
                    "timestamp_text": previous_timestamp_text or "Unknown",
                    "fail_count_since_last_success": "",
                    "last_sync_attempt_time": "",
                    "last_sync_response_time": "",
                    "now_tp": "",
                    "interval_seconds": "",
                    "next_sync_tp": "",
                }
                next_index = line_number + 1
                while next_index < len(all_lines):
                    next_line = all_lines[next_index].rstrip("\n")
                    if timestamp_pattern.match(next_line):
                        break
                    if not next_line.strip():
                        next_index += 1
                        break

                    key_value_match = key_value_pattern.match(next_line.strip())
                    if key_value_match:
                        schedule_key = key_value_match.group(1).strip().lower()
                        schedule_value = key_value_match.group(2).strip()
                        if schedule_key == "failcntsincelastsyncsuccess":
                            schedule_snapshot["fail_count_since_last_success"] = schedule_value
                            stats_counter["failure_counters_logged"] += 1
                        elif schedule_key == "lastsyncattempttime":
                            schedule_snapshot["last_sync_attempt_time"] = schedule_value
                        elif schedule_key == "lastsyncresponsetime":
                            schedule_snapshot["last_sync_response_time"] = schedule_value
                        elif schedule_key == "nowtp":
                            schedule_snapshot["now_tp"] = schedule_value
                        elif schedule_key == "intervalseconds":
                            schedule_snapshot["interval_seconds"] = schedule_value
                        elif schedule_key == "nextsynctp":
                            schedule_snapshot["next_sync_tp"] = schedule_value
                    next_index += 1

                if any(
                    schedule_snapshot.get(field)
                    for field in (
                        "fail_count_since_last_success",
                        "last_sync_attempt_time",
                        "last_sync_response_time",
                        "now_tp",
                        "interval_seconds",
                        "next_sync_tp",
                    )
                ):
                    schedule_snapshots.append(schedule_snapshot)

            if on_config_sync_stats_pattern.search(line) or stats_header_pattern.search(line):
                stats_counter["stats_notifications"] += 1
                stats_block = {
                    "path": log_path,
                    "line_number": absolute_line_number,
                    "timestamp": previous_timestamp,
                    "timestamp_text": previous_timestamp_text or "Unknown",
                    "raw_lines": [line],
                    "enrollment_id": "",
                    "last_successful_sync": "",
                    "failures_since_last_successful_sync": "",
                    "sync_interval_minutes": "",
                    "server_connectivity": "",
                }

                next_index = line_number + 1
                while next_index < len(all_lines):
                    next_line = all_lines[next_index].rstrip("\n")
                    if timestamp_pattern.match(next_line):
                        break
                    if not next_line.strip():
                        next_index += 1
                        break

                    stats_block["raw_lines"].append(next_line)
                    key_value_match = key_value_pattern.match(next_line.strip())
                    if key_value_match:
                        key = key_value_match.group(1).strip().lower()
                        value = key_value_match.group(2).strip()
                        if key == "enrollment id":
                            stats_block["enrollment_id"] = value
                            if value:
                                unique_enrollment_ids.add(value)
                        elif key == "last successful sync":
                            stats_block["last_successful_sync"] = value
                        elif key == "failures since last successful sync":
                            stats_block["failures_since_last_successful_sync"] = value
                        elif key == "sync interval (minutes)":
                            stats_block["sync_interval_minutes"] = value
                        elif key == "server connectivity":
                            stats_block["server_connectivity"] = value
                    next_index += 1

                stats_notifications.append(stats_block)
                line_number = next_index
                continue

            line_number += 1

    configsync_entries.sort(
        key=lambda entry: (
            entry["timestamp"] is None,
            entry["timestamp"] or datetime.max,
            entry["path"],
            entry["line_number"],
        )
    )
    if len(configsync_entries) > max_matches:
        configsync_entries = configsync_entries[-max_matches:]

    configsync_error_entries.sort(
        key=lambda entry: (
            entry["timestamp"] is None,
            entry["timestamp"] or datetime.max,
            entry["path"],
            entry["line_number"],
        )
    )
    if len(configsync_error_entries) > max_matches:
        configsync_error_entries = configsync_error_entries[-max_matches:]

    stats_notifications.sort(
        key=lambda entry: (
            entry["timestamp"] is None,
            entry["timestamp"] or datetime.max,
            entry["path"],
            entry["line_number"],
        )
    )

    timestamps = [entry["timestamp"] for entry in configsync_entries if entry.get("timestamp")]
    return {
        "total_hits": len(configsync_entries),
        "timeframe_start": min(timestamps) if timestamps else None,
        "timeframe_end": max(timestamps) if timestamps else None,
        "entries": configsync_entries,
        "error_entries": configsync_error_entries,
        "stats_notifications": stats_notifications,
        "schedule_snapshots": schedule_snapshots,
        "stats": {
            "sent_requests": stats_counter.get("sent_requests", 0),
            "already_latest": stats_counter.get("already_latest", 0),
            "sync_success": stats_counter.get("sync_success", 0),
            "schedule_calls": stats_counter.get("schedule_calls", 0),
            "failure_counters_logged": stats_counter.get("failure_counters_logged", 0),
            "stats_notifications": stats_counter.get("stats_notifications", 0),
            "enrollment_ids": sorted(unique_enrollment_ids),
        },
    }


def _normalize_evidence_signature(line):
    """Collapse a raw log line into a stable, human-readable signature.

    Strips leading timestamps, file:line references and masks volatile tokens
    (IPs, ports, numbers, hex ids) so that many near-identical log lines fold
    into a single grouped signature for the Health Snapshot cards.
    """
    text = " ".join(str(line or "").split())
    text = re.sub(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*", "", text)
    text = re.sub(r"\b[\w./-]+\.(?:cpp|cc|cxx|c|hpp|h|py|go|rs|js|mm):\d+\b", "", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", text)
    text = re.sub(r"\b0x[0-9a-fA-F]+\b", "<hex>", text)
    text = re.sub(r"\b[0-9a-fA-F]{16,}\b", "<id>", text)
    text = re.sub(r"\b\d+\b", "N", text)
    text = " ".join(text.split())
    if len(text) > 120:
        text = f"{text[:120]}..."
    return text or "(no detail)"


def group_evidence_lines(lines, limit=5):
    """Group similar evidence lines into deduplicated signatures with counts.

    Returns a list of ``{"label": signature, "count": n}`` ordered by frequency
    so a card can show "112x reconnect to headend" instead of 112 raw log rows.
    """
    counter = {}
    order = []
    for line in lines or []:
        signature = _normalize_evidence_signature(line)
        if signature not in counter:
            counter[signature] = 0
            order.append(signature)
        counter[signature] += 1
    order.sort(key=lambda sig: counter[sig], reverse=True)
    return [{"label": sig, "count": counter[sig]} for sig in order[:limit]]


# Ordered cause buckets for server-connectivity events. The first matching
# pattern wins, so more-specific causes are listed before the generic fallback.
_CONNECTIVITY_CAUSE_RULES = [
    (
        "dns_doh",
        "DNS / DoH resolution timed out",
        "Secure Access DoH resolver did not answer (request_timeout / RequestTimedOut).",
        re.compile(r"dnsflow|dohclient|\bdoh\b|resolver|request_?timeout|requesttimedout|dns\s+(?:resolution|resolve)", re.IGNORECASE),
    ),
    (
        "headend_tunnel",
        "Headend / tunnel unreachable",
        "The HTTP/2 tunnel to the Secure Access headend could not carry data.",
        re.compile(r"http2mux|\btunnel\b|ztnatransport|transportmanager|stream=|headend|h2\b", re.IGNORECASE),
    ),
    (
        "network_captive",
        "Network unreachable / captive portal",
        "The underlying network blocked the reachability probe (ServerUnreachable / connecttest).",
        re.compile(r"serverunreachable|captiveportal|connecttest|msftconnecttest|network\s+unreachable|host\s+unreachable|network\s+is\s+not\s+present|no\s+route", re.IGNORECASE),
    ),
    (
        "tls_cert",
        "TLS / certificate failure",
        "The secure channel to the headend failed to negotiate.",
        re.compile(r"tls\s+handshake|\bssl\b|certificate|handshake\s+failed|sec_e", re.IGNORECASE),
    ),
    (
        "posture_dha",
        "Device posture (DHA) not connected",
        "The Device Health Agent IPC/posture channel was down.",
        re.compile(r"\bdha\b|posture", re.IGNORECASE),
    ),
]


def categorize_connectivity_causes(lines):
    """Bucket server-connectivity event lines into human causes for a diagram.

    Returns a list of ``{"key", "label", "hint", "count"}`` ordered by count so
    the Health Snapshot can draw a cause->effect diagram instead of raw log rows.
    """
    counter = {}
    hints = {}
    labels = {}
    for line in lines or []:
        text = str(line or "")
        matched_key = "other_reconnect"
        for key, label, hint, pattern in _CONNECTIVITY_CAUSE_RULES:
            if pattern.search(text):
                matched_key = key
                labels[key] = label
                hints[key] = hint
                break
        else:
            labels[matched_key] = "Other reconnect / reachability event"
            hints[matched_key] = "Generic reconnect or reachability activity."
        counter[matched_key] = counter.get(matched_key, 0) + 1

    causes = [
        {"key": key, "label": labels[key], "hint": hints[key], "count": count}
        for key, count in counter.items()
    ]
    causes.sort(key=lambda item: item["count"], reverse=True)
    return causes


def build_zta_preview_signals(root_dir):
    """Lightweight, best-effort summary of key ZTA-log findings for the bundle preview.

    Returns a structured dict consumed by the ZTA Health Snapshot cards. In
    addition to the raw per-category counts it produces an interpreted
    ``assessment`` (one entry per card, each with a severity, plain-English
    summary, "what it means", "impact" and grouped evidence) plus an overall
    ``verdict`` synthesising the worst-case health of the ZTA agent.
    """
    signals = {
        "available": False,
        "flows": {"count": 0, "tcp": 0, "udp": 0, "details": []},
        "tnd": {"detected": False, "on_trusted_network": False, "status": "Not detected", "details": []},
        "user_pause": {"detected": False, "paused_by_user": False, "status": "Not detected", "details": []},
        "configuration_sync_errors": {"detected": False, "count": 0, "details": []},
        "server_connectivity_errors": {"detected": False, "count": 0, "details": []},
        "enrollment_errors": {"detected": False, "count": 0, "total_attempts": 0, "details": []},
    }

    zta_log_paths = find_module_log_text_files(root_dir, "Zero Trust Access")
    if not zta_log_paths:
        return signals

    signals["available"] = True

    detail_sample_limit = 12

    def truncate_line(text, limit=220):
        collapsed = " ".join(str(text or "").split())
        return collapsed if len(collapsed) <= limit else f"{collapsed[:limit]}..."

    # Single pass over the ZTA logs for redirected flows + enrollment completions.
    flow_count = 0
    tcp_count = 0
    udp_count = 0
    flow_samples = []
    dest_counter = {}
    enrollment_total = 0
    enrollment_failures = 0
    enrollment_samples = []
    enrollment_failure_lines = []
    completion_phrase = "Notifying enrollment completion with result:"

    for log_path in zta_log_paths:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    if "new redirected flow:" in raw_line:
                        parsed_flow = parse_new_redirected_flow_line(raw_line)
                        if parsed_flow:
                            flow_count += 1
                            if parsed_flow.get("protocol") == "TCP":
                                tcp_count += 1
                            elif parsed_flow.get("protocol") == "UDP":
                                udp_count += 1
                            destination = str(parsed_flow.get("destination", "") or "").strip()
                            if destination:
                                dest_counter[destination] = dest_counter.get(destination, 0) + 1
                            if len(flow_samples) < detail_sample_limit:
                                flow_samples.append(
                                    f"{parsed_flow.get('timestamp', '')} {parsed_flow.get('protocol', '')} "
                                    f"{parsed_flow.get('destination', '')}:{parsed_flow.get('destination_port', '')}"
                                    f" (process {parsed_flow.get('process_name', 'Unknown')})".strip()
                                )
                    if completion_phrase in raw_line:
                        enrollment_total += 1
                        result_text = raw_line.split(completion_phrase, 1)[1].strip()
                        is_failure = "error" in result_text.lower() or "fail" in result_text.lower()
                        if is_failure:
                            enrollment_failures += 1
                            enrollment_failure_lines.append(f"result: {result_text}")
                        if len(enrollment_samples) < detail_sample_limit:
                            timestamp_match = re.match(
                                r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)", raw_line
                            )
                            timestamp_prefix = f"{timestamp_match.group(1)} " if timestamp_match else ""
                            enrollment_samples.append(
                                truncate_line(f"{timestamp_prefix}result: {result_text}")
                            )
        except OSError:
            continue

    signals["flows"] = {
        "count": flow_count,
        "tcp": tcp_count,
        "udp": udp_count,
        "details": flow_samples,
    }
    signals["enrollment_errors"] = {
        "detected": enrollment_failures > 0,
        "count": enrollment_failures,
        "total_attempts": enrollment_total,
        "details": enrollment_samples,
    }

    # Trusted Network Detection.
    try:
        tnd_result = analyze_trusted_network_detection_runtime(root_dir)
        tnd_flows = tnd_result.get("flows", {}) or {}
        on_trusted_network = any(info.get("paused_by_tnd") for info in tnd_flows.values())
        tnd_detected = bool(tnd_result.get("found"))
        tnd_details = []
        for flow_key, info in tnd_flows.items():
            if info.get("runtime_found"):
                tnd_details.append(f"{flow_key}: {info.get('runtime_status', 'Unknown')}")
        for snapshot in (tnd_result.get("network_snapshots", []) or [])[:detail_sample_limit]:
            servers = ", ".join(snapshot.get("dns_servers", []) or [])
            snippet = f"{snapshot.get('timestamp_text', 'Unknown')} network snapshot"
            if snapshot.get("dns_domain"):
                snippet += f" domain={snapshot.get('dns_domain')}"
            if servers:
                snippet += f" dns={servers}"
            tnd_details.append(truncate_line(snippet))
        signals["tnd"] = {
            "detected": tnd_detected,
            "on_trusted_network": on_trusted_network,
            "status": (
                "On trusted network" if on_trusted_network
                else ("Detected" if tnd_detected else "Not detected")
            ),
            "details": tnd_details[:detail_sample_limit],
        }
    except Exception:
        pass

    # User Pause.
    try:
        pause_result = analyze_user_pause_runtime(root_dir)
        pause_flows = pause_result.get("flows", {}) or {}
        paused_by_user = any(info.get("paused_by_user") for info in pause_flows.values())
        pause_requested = any(info.get("pause_requested") for info in pause_flows.values())
        pause_details = []
        for flow_key, info in pause_flows.items():
            if not info.get("runtime_found"):
                continue
            snippet = f"{flow_key}: {info.get('runtime_status', 'Unknown')}"
            pause_start = info.get("pause_start", "")
            pause_end = info.get("pause_end", "")
            if pause_start and pause_end and pause_start != pause_end:
                snippet += f" ({pause_start} -> {pause_end})"
            elif pause_start or pause_end:
                snippet += f" ({pause_start or pause_end})"
            pause_details.append(truncate_line(snippet))
        signals["user_pause"] = {
            "detected": bool(pause_result.get("pause_initiated") or pause_requested or paused_by_user),
            "paused_by_user": paused_by_user,
            "status": (
                "Paused by user" if paused_by_user
                else ("Pause requested" if pause_requested else "Not detected")
            ),
            "details": pause_details[:detail_sample_limit],
        }
    except Exception:
        pass

    # Configuration sync errors.
    config_sync_lines = []
    try:
        config_sync = collect_configuration_sync_error_context(root_dir)
        config_sync_entries = config_sync.get("error_entries", []) or []
        config_sync_lines = [str(entry.get("line", "") or "") for entry in config_sync_entries]
        signals["configuration_sync_errors"] = {
            "detected": len(config_sync_entries) > 0,
            "count": len(config_sync_entries),
            "details": [
                truncate_line(f"{entry.get('timestamp_text', 'Unknown')} {entry.get('line', '')}")
                for entry in config_sync_entries[-detail_sample_limit:]
            ],
        }
    except Exception:
        pass

    # Server connectivity errors.
    connectivity_lines = []
    try:
        connectivity_matches = find_server_connectivity_error_lines(root_dir)
        connectivity_matches = connectivity_matches or []
        # The shared detector uses broad patterns that also match benign status
        # lines (e.g. "Server connectivity: Ok"); drop those for the preview signal.
        benign_connectivity_pattern = re.compile(
            r":\s*(?:ok|unknown|none|n/?a|pending|initializing|checking|connecting)\b"
            r"|=\s*ok\b|\bsuccessful\b|\bsucceeded\b|\bconnected\b|\breachable\b|\bhealthy\b",
            re.IGNORECASE,
        )
        connectivity_errors = [
            entry for entry in connectivity_matches
            if not benign_connectivity_pattern.search(str(entry.get("line", "")))
        ]
        connectivity_lines = [str(entry.get("line", "") or "") for entry in connectivity_errors]
        signals["server_connectivity_errors"] = {
            "detected": len(connectivity_errors) > 0,
            "count": len(connectivity_errors),
            "details": [
                truncate_line(f"{entry.get('timestamp_text', 'Unknown')} {entry.get('line', '')}")
                for entry in connectivity_errors[-detail_sample_limit:]
            ],
        }
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Interpreted assessment: turn raw counts into plain-English cards.
    # ------------------------------------------------------------------
    def plural(count, word):
        return f"{count} {word}{'' if count == 1 else 's'}"

    assessment = []

    # Enrollment.
    if enrollment_failures > 0:
        assessment.append({
            "label": "Enrollment",
            "severity": "critical",
            "chip": plural(enrollment_failures, "failure"),
            "metric": plural(enrollment_total, "attempt"),
            "summary": f"{enrollment_failures} of {enrollment_total} enrollment attempts reported an error.",
            "meaning": "The device could not fully enroll into Zero Trust Access.",
            "impact": "Private-app access through ZTA will not work until enrollment succeeds.",
            "suggestions": [
                "Confirm the device can reach the ZTA enrollment endpoint (headend / SSE) and that DNS resolves it.",
                "Check the enrollment certificate and device posture (DHA) state in the ZTA enrollment JSON.",
                "Have the user sign out and re-enroll Zero Trust Access from Cisco Secure Client.",
            ],
            "groups": group_evidence_lines(enrollment_failure_lines),
        })
    elif enrollment_total > 0:
        assessment.append({
            "label": "Enrollment",
            "severity": "ok",
            "chip": "Enrolled",
            "metric": plural(enrollment_total, "attempt"),
            "summary": f"Enrollment completed successfully ({plural(enrollment_total, 'completion event')}, 0 errors).",
            "meaning": "The device is enrolled into Zero Trust Access.",
            "impact": "None - enrollment is healthy.",
            "groups": [],
        })
    else:
        assessment.append({
            "label": "Enrollment",
            "severity": "info",
            "chip": "No data",
            "metric": "0 attempts",
            "summary": "No enrollment completion traces were found in the logs.",
            "meaning": "The agent was likely already enrolled before this capture, or enrollment logging is absent.",
            "impact": "Not necessarily a problem.",
            "groups": [],
        })

    # Configuration sync.
    config_sync_count = len(config_sync_lines)
    if config_sync_count > 0:
        assessment.append({
            "label": "Config Sync",
            "severity": "warning",
            "chip": plural(config_sync_count, "error"),
            "metric": "Policy refresh",
            "summary": f"{plural(config_sync_count, 'configuration-sync error')} were logged.",
            "meaning": "The agent may be running stale or partial policy because it could not refresh its configuration from the cloud.",
            "impact": "Access decisions could be based on outdated policy until sync recovers.",
            "suggestions": [
                "Verify the agent can reach the cloud config service - a proxy or firewall may be blocking policy refresh.",
                "Check whether the errors cluster around one time or keep repeating (a one-off may have already recovered).",
                "Confirm the enrolled org / policy is still valid and was not deleted or re-provisioned.",
            ],
            "groups": group_evidence_lines(config_sync_lines),
        })
    else:
        assessment.append({
            "label": "Config Sync",
            "severity": "ok",
            "chip": "In sync",
            "metric": "Policy refresh",
            "summary": "Configuration synced without errors.",
            "meaning": "The agent is running current policy from the cloud.",
            "impact": "None.",
            "groups": [],
        })

    # Server connectivity.
    connectivity_count = len(connectivity_lines)
    if connectivity_count > 0:
        connectivity_causes = categorize_connectivity_causes(connectivity_lines)
        assessment.append({
            "label": "Server Connectivity",
            "severity": "warning",
            "chip": plural(connectivity_count, "event"),
            "metric": "Headend reachability",
            "summary": f"{plural(connectivity_count, 'reachability / reconnect event')} were logged, grouped by cause below.",
            "meaning": "Check reachability to the ZTA headend / DoH resolver. To isolate further, take Wireshark captures on the client side and collect detailed ZTA-level tracing.",
            "impact": "Occasional reconnects are normal; only a sustained failure would block private-app access and DNS steering.",
            "diagram": {
                "source": "Cisco Secure Client (ZTA)",
                "target": "Secure Access headend / DoH resolver",
                "causes": connectivity_causes,
            },
            "suggestions": [
                "Check the failing Flows above - repeatedly failing redirected flows can drive these server-connectivity events.",
                "Verify the ZTA network requirements are met: allow *.ztna.sse.cisco.com, *.zpc.sse.cisco.com and *.tia.sse.cisco.com on 443 (TCP and UDP). See https://securitydocs.cisco.com/docs/csa/olh/118990.dita",
                "Correlate the timestamps with network changes (Wi-Fi switch, VPN connect/disconnect, TND) to explain the reconnects.",
            ],
            "groups": group_evidence_lines(connectivity_lines),
        })
    else:
        assessment.append({
            "label": "Server Connectivity",
            "severity": "ok",
            "chip": "Reachable",
            "metric": "Headend reachability",
            "summary": "No server-connectivity errors were logged.",
            "meaning": "The agent maintained a healthy connection to the ZTA headend.",
            "impact": "None.",
            "groups": [],
        })

    # Flows (informational).
    top_destinations = sorted(dest_counter.items(), key=lambda item: item[1], reverse=True)[:5]
    flow_groups = [{"label": dest, "count": count} for dest, count in top_destinations]
    if flow_count > 0:
        assessment.append({
            "label": "Flows",
            "severity": "info",
            "chip": plural(flow_count, "flow"),
            "metric": f"TCP {tcp_count} / UDP {udp_count}",
            "summary": f"{plural(flow_count, 'flow')} were steered through Zero Trust Access.",
            "meaning": "Private-app traffic was actively redirected through the ZTA tunnel.",
            "impact": "Confirms ZTA steering is functioning.",
            "groups": flow_groups,
        })
    else:
        assessment.append({
            "label": "Flows",
            "severity": "info",
            "chip": "None",
            "metric": "TCP 0 / UDP 0",
            "summary": "No redirected flows were captured.",
            "meaning": "No private-app traffic was steered through ZTA during this capture.",
            "impact": "Expected if the user did not access private apps.",
            "groups": [],
        })

    # Trusted Network Detection (informational).
    tnd_signal = signals.get("tnd", {}) or {}
    if tnd_signal.get("on_trusted_network"):
        assessment.append({
            "label": "TND Detection",
            "severity": "info",
            "chip": "Trusted",
            "metric": "Trusted network",
            "summary": "The device was on a trusted network; ZTA steering paused as designed.",
            "meaning": "Trusted Network Detection matched, so traffic bypassed the tunnel.",
            "impact": "Expected behavior on corporate / trusted networks.",
            "groups": [],
        })
    elif tnd_signal.get("detected"):
        assessment.append({
            "label": "TND Detection",
            "severity": "info",
            "chip": "Evaluated",
            "metric": "Trusted network",
            "summary": "Trusted Network Detection ran; the device was treated as off-trusted-network.",
            "meaning": "TND evaluated the network and did not match a trusted profile, so steering stayed active.",
            "impact": "Expected behavior on untrusted / home networks.",
            "groups": [],
        })
    else:
        assessment.append({
            "label": "TND Detection",
            "severity": "info",
            "chip": "Not detected",
            "metric": "Trusted network",
            "summary": "No trusted-network-detection activity was logged.",
            "meaning": "Either TND is not configured or it did not evaluate during this capture.",
            "impact": "None.",
            "groups": [],
        })

    # User Pause (informational, but surfaced as a warning because it explains outages).
    pause_signal = signals.get("user_pause", {}) or {}
    if pause_signal.get("paused_by_user"):
        assessment.append({
            "label": "User Pause",
            "severity": "warning",
            "chip": "Paused",
            "metric": "Pause state",
            "summary": "The user paused Zero Trust Access.",
            "meaning": "Traffic steering was suspended by the user.",
            "impact": "Private-app access is disabled while paused - this can explain 'app not working' reports.",
            "suggestions": [
                "If the user reported 'app not working', a user pause is the likely cause - confirm whether they paused ZTA intentionally.",
                "Steering resumes automatically after the configured resume timeout - ask the user to resume ZTA or wait it out.",
            ],
            "groups": [],
        })
    elif pause_signal.get("status") == "Pause requested":
        assessment.append({
            "label": "User Pause",
            "severity": "info",
            "chip": "Requested",
            "metric": "Pause state",
            "summary": "A pause was requested but the device did not stay paused.",
            "meaning": "The user asked to pause ZTA; steering resumed shortly after.",
            "impact": "Brief interruption to private-app access.",
            "groups": [],
        })
    else:
        assessment.append({
            "label": "User Pause",
            "severity": "info",
            "chip": "Not paused",
            "metric": "Pause state",
            "summary": "No user-pause activity was logged.",
            "meaning": "The user did not pause Zero Trust Access.",
            "impact": "None.",
            "groups": [],
        })

    # Overall verdict = worst-case severity across the cards.
    critical_cards = [card for card in assessment if card["severity"] == "critical"]
    warning_cards = [card for card in assessment if card["severity"] == "warning"]
    if critical_cards:
        verdict_level = "problem"
        verdict_summary = "Action needed: " + "; ".join(card["summary"] for card in critical_cards)
    elif warning_cards:
        verdict_level = "degraded"
        labels = ", ".join(card["label"] for card in warning_cards)
        verdict_summary = f"Mostly healthy, but review {labels} below for details."
    else:
        verdict_level = "healthy"
        verdict_summary = "ZTA agent looks healthy - enrolled, configuration in sync, and server connectivity is clean."

    signals["assessment"] = assessment
    signals["verdict"] = {"level": verdict_level, "summary": verdict_summary}

    return signals


def filter_events_by_time_range(events, range_start, range_end, sample_limit=30):
    if range_start is None or range_end is None:
        return []

    matched = []
    for event in events:
        event_time = event.get("timestamp")
        if event_time is None:
            continue
        if range_start <= event_time <= range_end:
            matched.append(event)

    matched_sorted = sorted(
        matched,
        key=lambda item: item["timestamp"] if item.get("timestamp") else datetime.min,
        reverse=True,
    )
    return matched_sorted[:sample_limit]


def render_cached_config_files(json_paths, base_dir):
    rendered_sections = []

    for json_path in json_paths:
        relative_path = os.path.relpath(json_path, base_dir)
        try:
            with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
                payload = json.load(handle)
            pretty_json = json.dumps(payload, indent=2, sort_keys=True)
        except (json.JSONDecodeError, OSError) as exc:
            pretty_json = f"[!] Unable to read cached config: {exc}"

        rendered_sections.append(
            f"[Cached Config File] {relative_path}\n{pretty_json}"
        )

    return "\n\n".join(rendered_sections)


def search_cached_config_files(json_paths, base_dir, search_term):
    normalized_search_term = str(search_term).strip()
    if not normalized_search_term:
        return []

    lowered_search_term = normalized_search_term.lower()
    matches = []

    for json_path in json_paths:
        relative_path = os.path.relpath(json_path, base_dir)
        try:
            with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
                payload = json.load(handle)
            pretty_json_lines = json.dumps(payload, indent=2, sort_keys=True).splitlines()
            flow_ranges = build_cached_config_flow_ranges(payload, pretty_json_lines)
        except (json.JSONDecodeError, OSError) as exc:
            matches.append({
                "path": relative_path,
                "error": str(exc),
                "matched_lines": [],
            })
            continue

        matched_lines = []
        for line_index, line_text in enumerate(pretty_json_lines):
            if lowered_search_term in line_text.lower():
                flow = classify_cached_config_match_flow(pretty_json_lines, line_index, flow_ranges)
                direction = classify_cached_config_match_direction(pretty_json_lines, line_index)
                matched_lines.append({
                    "line_number": line_index + 1,
                    "line_text": line_text,
                    "flow": flow,
                    "direction": direction,
                })

        matched_lines = collapse_overlapping_cached_config_matches(
            matched_lines,
            normalized_search_term,
        )

        if matched_lines:
            matches.append({
                "path": relative_path,
                "error": None,
                "matched_lines": matched_lines,
            })

    return matches


def summarize_cached_config_match_flows(cached_config_matches):
    flows = set()
    for match in cached_config_matches:
        for matched_line in match.get("matched_lines", []):
            flow = matched_line.get("flow")
            if flow in {"SPA", "SIA", "SPA and SIA"}:
                flows.add(flow)
    return flows


def collapse_overlapping_cached_config_matches(matched_lines, search_term):
    normalized_search_term = str(search_term).strip().lower().rstrip('.')
    if not normalized_search_term:
        return matched_lines

    wildcard_matches = []
    exact_fqdn_matches = []

    for matched_line in matched_lines:
        extracted_value = extract_cached_config_match_value(matched_line.get("line_text", ""))
        normalized_value = extracted_value.lower().rstrip('.')

        if normalized_value.startswith("*.") and is_fqdn_entry(normalized_value[2:]):
            wildcard_matches.append(matched_line)
        elif is_fqdn_entry(normalized_value):
            exact_fqdn_matches.append(matched_line)

    if not exact_fqdn_matches or not wildcard_matches:
        return matched_lines

    updated_matches = []
    wildcard_notes_by_line = {}
    suppressed_wildcard_lines = set()

    for exact_match in exact_fqdn_matches:
        exact_value = extract_cached_config_match_value(exact_match.get("line_text", ""))
        covering_wildcards = []
        for wildcard_match in wildcard_matches:
            if wildcard_match.get("flow") != exact_match.get("flow"):
                continue
            if wildcard_match.get("direction") != exact_match.get("direction"):
                continue

            wildcard_value = extract_cached_config_match_value(wildcard_match.get("line_text", ""))
            if wildcard_value and fqdn_matches_rule(exact_value, wildcard_value):
                covering_wildcards.append(wildcard_value)
                suppressed_wildcard_lines.add(wildcard_match.get("line_number"))

        if covering_wildcards:
            wildcard_notes_by_line[exact_match.get("line_number")] = (
                f" [also matched by wildcard: {', '.join(sorted(set(covering_wildcards)))}]"
            )

    for matched_line in matched_lines:
        line_number = matched_line.get("line_number")
        if line_number in suppressed_wildcard_lines:
            continue

        wildcard_note = wildcard_notes_by_line.get(line_number, "")
        if wildcard_note:
            updated_line = dict(matched_line)
            updated_line["line_text"] = f"{matched_line['line_text']}{wildcard_note}"
            updated_matches.append(updated_line)
            continue

        updated_matches.append(matched_line)

    return updated_matches


def extract_cached_config_match_value(line_text):
    match = re.search(r'"([^"]+)"', str(line_text))
    if not match:
        return ""
    return match.group(1).strip()


def build_cached_config_flow_ranges(payload, pretty_json_lines):
    flow_ranges = []

    def build_object_ranges(lines):
        ranges = []
        object_stack = []

        for line_index, line_text in enumerate(lines):
            for character in line_text:
                if character == '{':
                    object_stack.append(line_index)
                elif character == '}':
                    if object_stack:
                        start_index = object_stack.pop()
                        ranges.append((start_index, line_index))

        return ranges

    def find_innermost_object_range(ranges, line_index):
        containing_ranges = [
            entry for entry in ranges if entry[0] <= line_index <= entry[1]
        ]
        if not containing_ranges:
            return None

        return min(containing_ranges, key=lambda entry: entry[1] - entry[0])

    ztna_config = get_case_insensitive_value(payload, "ztnaConfig", default={})
    resource_configs = get_case_insensitive_value(ztna_config, "resource_configs", default=[])
    object_ranges = build_object_ranges(pretty_json_lines)

    if isinstance(resource_configs, list):
        for index, config in enumerate(resource_configs):
            if not isinstance(config, dict):
                continue

            config_id = str(get_case_insensitive_value(config, "id", "")).strip().lower()
            if config_id == "spa_steering_config" or index == 0:
                flow = "SPA"
            elif config_id == "tia_steering_config" or index == 1:
                flow = "SIA"
            else:
                continue

            id_line = f'"id": "{config_id}"'
            matching_line_index = next(
                (line_index for line_index, line_text in enumerate(pretty_json_lines) if id_line in line_text),
                None,
            )
            if matching_line_index is None:
                continue

            range_match = find_innermost_object_range(object_ranges, matching_line_index)
            if range_match:
                flow_ranges.append({
                    "start": range_match[0],
                    "end": range_match[1],
                    "flow": flow,
                })

    return flow_ranges


def classify_cached_config_match_flow(pretty_json_lines, match_index, flow_ranges):
    matching_flows = {
        entry["flow"]
        for entry in flow_ranges
        if entry["start"] <= match_index <= entry["end"]
    }

    if matching_flows == {"SPA", "SIA"}:
        return 'SPA and SIA'
    if matching_flows == {"SPA"}:
        return 'SPA'
    if matching_flows == {"SIA"}:
        return 'SIA'

    line_text = pretty_json_lines[match_index].lower()
    if '.zpc.sse.cisco.com' in line_text or '"spa_' in line_text:
        return 'SPA'
    if '.tia.sse.cisco.com' in line_text or '"tia_' in line_text:
        return 'SIA'
    return 'Unknown'


def classify_cached_config_match_direction(pretty_json_lines, match_index):
    direction_ranges = build_cached_config_direction_ranges(pretty_json_lines)

    matching_directions = {
        entry["direction"]
        for entry in direction_ranges
        if entry["start"] <= match_index <= entry["end"]
    }

    if matching_directions == {"Include", "Exclude"}:
        return 'Include and Exclude'
    if matching_directions == {"Include"}:
        return 'Include'
    if matching_directions == {"Exclude"}:
        return 'Exclude'

    line_text = pretty_json_lines[match_index].lower()
    if '"include": [' in line_text:
        return 'Include'
    if '"exclude": [' in line_text:
        return 'Exclude'
    return 'Unknown'


def build_cached_config_direction_ranges(pretty_json_lines):
    direction_ranges = []
    array_stack = []
    pending_array_direction = None

    for line_index, line_text in enumerate(pretty_json_lines):
        stripped_line = line_text.strip().lower()

        if '"include": [' in stripped_line:
            pending_array_direction = 'Include'
        elif '"exclude": [' in stripped_line:
            pending_array_direction = 'Exclude'

        for character in line_text:
            if character == '[':
                array_stack.append({
                    "start": line_index,
                    "direction": pending_array_direction,
                })
                pending_array_direction = None
            elif character == ']':
                if array_stack:
                    array_info = array_stack.pop()
                    if array_info["direction"]:
                        direction_ranges.append({
                            "start": array_info["start"],
                            "end": line_index,
                            "direction": array_info["direction"],
                        })

    return direction_ranges


def get_case_insensitive_value(mapping, target_key, default=None):
    if not isinstance(mapping, dict):
        return default
    target = str(target_key).lower()
    for key, value in mapping.items():
        if str(key).lower() == target:
            return value
    return default


def flatten_to_strings(value):
    values = []
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            values.append(stripped)
    elif isinstance(value, (bool, int, float)):
        values.append(str(value))
    elif isinstance(value, list):
        for item in value:
            values.extend(flatten_to_strings(item))
    elif isinstance(value, dict):
        for _, item in value.items():
            values.extend(flatten_to_strings(item))
    return values


def extract_include_exclude_from_resource_configs(json_path, steering_config_id):
    with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
        payload = json.load(handle)

    config_objects = []

    def walk_for_resource_configs(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).lower() == "resource_configs" and isinstance(value, list):
                    for entry in value:
                        if not isinstance(entry, dict):
                            continue
                        entry_id = str(get_case_insensitive_value(entry, "id", "")).strip().lower()
                        if entry_id == str(steering_config_id).strip().lower():
                            config_objects.append(entry)
                walk_for_resource_configs(value)
        elif isinstance(node, list):
            for item in node:
                walk_for_resource_configs(item)

    walk_for_resource_configs(payload)

    cidr_include = []
    cidr_exclude = []
    fqdn_include = []
    fqdn_exclude = []
    dns_include = []
    dns_exclude = []

    for config in config_objects:
        cidr_section = get_case_insensitive_value(config, "CIDR", default={})
        fqdn_section = get_case_insensitive_value(config, "fqdn", default={})
        dns_section = get_case_insensitive_value(config, "dns", default={})

        cidr_include.extend(flatten_to_strings(get_case_insensitive_value(cidr_section, "include", default=[])))
        cidr_exclude.extend(flatten_to_strings(get_case_insensitive_value(cidr_section, "exclude", default=[])))
        fqdn_include.extend(flatten_to_strings(get_case_insensitive_value(fqdn_section, "include", default=[])))
        fqdn_exclude.extend(flatten_to_strings(get_case_insensitive_value(fqdn_section, "exclude", default=[])))
        dns_include.extend(flatten_to_strings(get_case_insensitive_value(dns_section, "include", default=[])))
        dns_exclude.extend(flatten_to_strings(get_case_insensitive_value(dns_section, "exclude", default=[])))

    return {
        "matched_steering_config": len(config_objects),
        "cidr_include": sorted(set(cidr_include)),
        "cidr_exclude": sorted(set(cidr_exclude)),
        "fqdn_include": sorted(set(fqdn_include)),
        "fqdn_exclude": sorted(set(fqdn_exclude)),
        "dns_include": sorted(set(dns_include)),
        "dns_exclude": sorted(set(dns_exclude)),
    }


def extract_spa_dns_include_entries(json_path):
    with open(json_path, "r", encoding="utf-8", errors="ignore") as handle:
        payload = json.load(handle)

    matched_configs = []
    used_index_zero_fallback = False

    def walk(node):
        nonlocal used_index_zero_fallback
        if isinstance(node, dict):
            ztna_config = get_case_insensitive_value(node, "ztnaConfig", default={})
            if isinstance(ztna_config, dict):
                resource_configs = get_case_insensitive_value(ztna_config, "resource_configs", default=[])
                if isinstance(resource_configs, list):
                    for index, config in enumerate(resource_configs):
                        if not isinstance(config, dict):
                            continue
                        config_id = str(get_case_insensitive_value(config, "id", "")).strip().lower()
                        # Evaluate the entire cached config so SRV records steered by
                        # either SPA or SIA are found (matches Flow Analysis behaviour).
                        if config_id in ("spa_steering_config", "tia_steering_config"):
                            matched_configs.append(config)
                        elif index == 0:
                            matched_configs.append(config)
                            used_index_zero_fallback = True

            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)

    dns_include_entries = []
    for config in matched_configs:
        dns_section = get_case_insensitive_value(config, "dns", default={})
        dns_include_entries.extend(
            flatten_to_strings(get_case_insensitive_value(dns_section, "include", default=[]))
        )

    return {
        "matched_spa_resource_configs": len(matched_configs),
        "used_index_zero_fallback": used_index_zero_fallback,
        "dns_include": sorted(set(dns_include_entries)),
    }


def fqdn_matches_rule(target_fqdn, rule):
    target = str(target_fqdn).strip().lower().rstrip('.')
    candidate = str(rule).strip().lower().rstrip('.')
    if not target or not candidate:
        return False

    if candidate == "*":
        return True

    if candidate.startswith("*."):
        suffix = candidate[2:]
        return target == suffix or target.endswith("." + suffix)
    return target == candidate


def rule_is_exact_or_subdomain_of_target(target_fqdn, rule):
    target = str(target_fqdn).strip().lower().rstrip('.')
    candidate = str(rule).strip().lower().rstrip('.')
    if not target or not candidate:
        return False

    if candidate == "*":
        return True

    if candidate.startswith("*."):
        candidate = candidate[2:]

    return candidate == target or candidate.endswith("." + target)


def srv_query_matches_rule(target_srv, rule):
    target = str(target_srv).strip().lower().rstrip('.')
    candidate = str(rule).strip().lower().rstrip('.')
    if not target or not candidate:
        return False

    # Keep wildcard support for completeness.
    if candidate.startswith("*."):
        suffix = candidate[2:]
        return target == suffix or target.endswith("." + suffix)

    # SRV queries may be entered as a suffix/domain fragment such as
    # "_msdcs.example.com" and should match full SRV records like
    # "_ldap._tcp.dc._msdcs.example.com".
    return (
        candidate == target
        or candidate.endswith("." + target)
        or target.endswith("." + candidate)
    )


def parse_spa_target_value(spa_target_value):
    raw_value = spa_target_value.strip()
    if not raw_value:
        return {"mode": "empty", "target": ""}

    upper_raw = raw_value.upper()
    if upper_raw.startswith("SRV:"):
        return {"mode": "srv", "target": raw_value[4:].strip()}
    if upper_raw.startswith("SRV "):
        return {"mode": "srv", "target": raw_value[4:].strip()}
    if upper_raw == "SRV":
        return {"mode": "srv", "target": ""}

    lowered = raw_value.lower().rstrip('.')
    normalized_labels = [label for label in lowered.split('.') if label]

    # Accept flexible SRV-style input, not only strict _service._proto.fqdn format.
    if lowered.startswith("_") and ("._tcp." in lowered or "._udp." in lowered):
        return {"mode": "srv", "target": raw_value}
    if "_tcp" in lowered or "_udp" in lowered:
        return {"mode": "srv", "target": raw_value}
    if any(label.startswith("_") for label in normalized_labels):
        return {"mode": "srv", "target": raw_value}

    return {"mode": "auto", "target": raw_value}


def evaluate_spa_target_against_include_exclude(
    spa_target_value,
    cidr_include,
    cidr_exclude,
    fqdn_include,
    fqdn_exclude,
    dns_include,
    dns_exclude,
):
    parsed_target = parse_spa_target_value(spa_target_value)
    mode = parsed_target["mode"]
    target = parsed_target["target"]

    if mode == "empty" or not target:
        target_type = "empty" if mode == "empty" else "srv"
        return {
            "target": "",
            "type": target_type,
            "cidr_include_matches": [],
            "cidr_exclude_matches": [],
            "dns_include_matches": [],
            "dns_exclude_matches": [],
            "classification": "not evaluated",
        }

    if mode == "srv":
        target_srv = target.lower().rstrip('.')
        dns_include_matches = [rule for rule in dns_include if srv_query_matches_rule(target_srv, rule)]
        dns_exclude_matches = [rule for rule in dns_exclude if srv_query_matches_rule(target_srv, rule)]

        if dns_exclude_matches and not dns_include_matches:
            classification = "excluded"
        elif dns_include_matches and not dns_exclude_matches:
            classification = "included"
        elif dns_include_matches and dns_exclude_matches:
            classification = "both include and exclude matched"
        else:
            classification = "no include/exclude match"

        return {
            "target": target,
            "type": "srv",
            "cidr_include_matches": [],
            "cidr_exclude_matches": [],
            "dns_include_matches": sorted(set(dns_include_matches)),
            "dns_exclude_matches": sorted(set(dns_exclude_matches)),
            "classification": classification,
        }

    try:
        target_ip = ipaddress.ip_address(target)
        cidr_include_matches = []
        cidr_exclude_matches = []

        for cidr in cidr_include:
            try:
                if target_ip in ipaddress.ip_network(cidr, strict=False):
                    cidr_include_matches.append(cidr)
            except ValueError:
                continue

        for cidr in cidr_exclude:
            try:
                if target_ip in ipaddress.ip_network(cidr, strict=False):
                    cidr_exclude_matches.append(cidr)
            except ValueError:
                continue

        if cidr_exclude_matches and not cidr_include_matches:
            classification = "excluded"
        elif cidr_include_matches and not cidr_exclude_matches:
            classification = "included"
        elif cidr_include_matches and cidr_exclude_matches:
            classification = "both include and exclude matched"
        else:
            classification = "no include/exclude match"

        return {
            "target": target,
            "type": "ip",
            "cidr_include_matches": sorted(set(cidr_include_matches)),
            "cidr_exclude_matches": sorted(set(cidr_exclude_matches)),
            "dns_include_matches": [],
            "dns_exclude_matches": [],
            "classification": classification,
        }
    except ValueError:
        target_fqdn = target.lower().rstrip('.')
        if not is_fqdn_entry(target_fqdn):
            return {
                "target": target,
                "type": "invalid",
                "cidr_include_matches": [],
                "cidr_exclude_matches": [],
                "dns_include_matches": [],
                "dns_exclude_matches": [],
                "classification": "invalid target format",
            }

        fqdn_include_matches = [
            rule
            for rule in fqdn_include
            if fqdn_matches_rule(target_fqdn, rule) or rule_is_exact_or_subdomain_of_target(target_fqdn, rule)
        ]
        fqdn_exclude_matches = [
            rule
            for rule in fqdn_exclude
            if fqdn_matches_rule(target_fqdn, rule) or rule_is_exact_or_subdomain_of_target(target_fqdn, rule)
        ]

        if fqdn_exclude_matches and not fqdn_include_matches:
            classification = "excluded"
        elif fqdn_include_matches and not fqdn_exclude_matches:
            classification = "included"
        elif fqdn_include_matches and fqdn_exclude_matches:
            classification = "both include and exclude matched"
        else:
            classification = "no include/exclude match"

        return {
            "target": target,
            "type": "fqdn",
            "cidr_include_matches": [],
            "cidr_exclude_matches": [],
            "dns_include_matches": sorted(set(fqdn_include_matches)),
            "dns_exclude_matches": sorted(set(fqdn_exclude_matches)),
            "classification": classification,
        }

@app.route('/')
def index():
    return render_template(
        'index.html',
        large_bundle_preview_threshold_mb=get_large_bundle_preview_threshold_mb(),
    )


@app.route('/features')
def features():
    return render_template('features.html')


@app.route('/inspect-bundle', methods=['POST'])
def inspect_bundle():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if not file.filename.lower().endswith('.zip'):
        return jsonify({"error": "Invalid file type. Please upload a .zip file."}), 400

    include_log_windows = request.form.get('include_log_windows', '1').strip().lower() in {
        '1', 'true', 'yes', 'on'
    }
    include_component_versions = request.form.get('include_component_versions', '1').strip().lower() in {
        '1', 'true', 'yes', 'on'
    }

    try:
        return jsonify(
            inspect_bundle_for_org_ids(
                file,
                include_log_windows=include_log_windows,
                include_component_versions=include_component_versions,
            )
        )
    except zipfile.BadZipFile:
        return jsonify({"error": "The uploaded payload is not a valid ZIP archive."}), 400

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    selected_module = request.form.get('module')
    if selected_module not in ['ZTA', 'VPN', 'Umbrella', 'Duo Desktop', 'UZTNA', 'EDLP']:
        return jsonify({"error": "Invalid module selected"}), 400

    zta_access_mode = request.form.get('zta_access_mode')
    allowed_zta_modes = ['SPA', 'SIA']
    show_full_cached_config = request.form.get('show_full_cached_config', '0').strip().lower() in {
        '1', 'true', 'yes', 'on'
    }

    if selected_module == 'ZTA' and zta_access_mode not in allowed_zta_modes and not show_full_cached_config:
        return jsonify({"error": "Invalid ZTA access type selected"}), 400

    spa_check_option = request.form.get('spa_check_option')
    spa_target_value = request.form.get('spa_target_value', '').strip()
    flow_selected_src_port = request.form.get('flow_selected_src_port', '').strip()
    flow_filter_destination_port = request.form.get('flow_filter_destination_port', '').strip()
    flow_filter_time_start = request.form.get('flow_filter_time_start', '').strip()
    flow_filter_time_end = request.form.get('flow_filter_time_end', '').strip()
    spa_enrollment_error_type = request.form.get('spa_enrollment_error_type', '').strip()
    srv_check_option = request.form.get('srv_check_option', '').strip()
    srv_config_filter_value = request.form.get('srv_config_filter_value', '').strip()
    srv_flow_filter_value = request.form.get('srv_flow_filter_value', '').strip()
    srv_flow_time_start = request.form.get('srv_flow_time_start', '').strip()
    srv_flow_time_end = request.form.get('srv_flow_time_end', '').strip()
    srv_selected_identifier = request.form.get('srv_selected_identifier', '').strip()
    evtx_max_records_per_file = request.form.get('evtx_max_records_per_file', '').strip()
    client_timezone_offset_minutes = request.form.get('client_timezone_offset_minutes', '').strip()
    cached_config_search_term = request.form.get('cached_config_search_term', '').strip()
    duo_posture_filter = request.form.get('duo_posture_filter', '').strip()
    allowed_spa_checks = [
        'Check Inclusions or Exclusions',
        'Check SIA Flow',
        'Check TCP or UDP Flow',
        'Check Enrollment Errors',
        'Check Configuration Sync',
        'Check Server Connectivity Errors',
        'Check Event Viewer Logs',
        'Check Trusted Network Detection',
        'Check User Pause Config',
        'SRV Check',
    ]
    checks_requiring_target = {
        'Check SIA Flow',
        'Check TCP or UDP Flow',
    }
    concise_include_exclude_output = (
        selected_module == 'ZTA'
        and zta_access_mode in {'SPA', 'SIA'}
        and spa_check_option in {'Check Inclusions or Exclusions', 'Check SIA Flow'}
    )
    concise_zta_check_output = (
        selected_module == 'ZTA'
        and bool(spa_check_option)
        and not show_full_cached_config
    )
    cached_config_search_only_output = (
        selected_module == 'ZTA'
        and show_full_cached_config
        and bool(cached_config_search_term)
    )

    if selected_module == 'ZTA':
        if not show_full_cached_config and zta_access_mode not in allowed_zta_modes:
            return jsonify({"error": "Invalid ZTA access type selected"}), 400
        if zta_access_mode == 'SPA' and spa_check_option and spa_check_option not in allowed_spa_checks:
            return jsonify({"error": "Invalid SPA analysis check selected"}), 400
        if (
            zta_access_mode == 'SPA'
            and not spa_check_option
            and not show_full_cached_config
        ):
            return jsonify({"error": "Invalid SPA analysis check selected"}), 400
        if (
            zta_access_mode == 'SIA'
            and spa_check_option
            and spa_check_option not in {
                'Check Inclusions or Exclusions',
                'Check SIA Flow',
                'Check Trusted Network Detection',
                'Check User Pause Config',
            }
        ):
            return jsonify({"error": "SIA currently supports only Check Cached Config or Check SIA Flow or Check Trusted Network Detection or Check User Pause Config"}), 400
        if (
            zta_access_mode == 'SIA'
            and not spa_check_option
            and not show_full_cached_config
        ):
            return jsonify({"error": "SIA currently supports only Check Cached Config or Check SIA Flow or Check Trusted Network Detection or Check User Pause Config"}), 400
        if spa_check_option in checks_requiring_target and not spa_target_value:
            return jsonify({"error": "Please provide IP or FQDN for the selected check"}), 400
        if (
            zta_access_mode == 'SPA'
            and spa_check_option == 'Check Enrollment Errors'
            and spa_enrollment_error_type not in {'Cert', 'SAML'}
        ):
            return jsonify({"error": "Please select Cert or SAML for Enrollment Failures check"}), 400

    flow_filter_start_dt = parse_ui_datetime_local(flow_filter_time_start)
    flow_filter_end_dt = parse_ui_datetime_local(flow_filter_time_end)
    srv_flow_start_dt = parse_ui_datetime_local(srv_flow_time_start)
    srv_flow_end_dt = parse_ui_datetime_local(srv_flow_time_end)

    if flow_filter_destination_port and not flow_filter_destination_port.isdigit():
        return jsonify({"error": "Flow port filter must be numeric"}), 400

    if flow_filter_time_start and flow_filter_start_dt is None:
        return jsonify({"error": "Invalid flow timeframe start format"}), 400

    if flow_filter_time_end and flow_filter_end_dt is None:
        return jsonify({"error": "Invalid flow timeframe end format"}), 400

    if (
        flow_filter_start_dt
        and flow_filter_end_dt
        and flow_filter_start_dt > flow_filter_end_dt
    ):
        return jsonify({"error": "Flow timeframe start must be earlier than end"}), 400

    if srv_flow_time_start and srv_flow_start_dt is None:
        return jsonify({"error": "Invalid SRV flow timeframe start format"}), 400

    if srv_flow_time_end and srv_flow_end_dt is None:
        return jsonify({"error": "Invalid SRV flow timeframe end format"}), 400

    if (
        srv_flow_start_dt
        and srv_flow_end_dt
        and srv_flow_start_dt > srv_flow_end_dt
    ):
        return jsonify({"error": "SRV flow timeframe start must be earlier than end"}), 400

    if client_timezone_offset_minutes:
        try:
            int(client_timezone_offset_minutes)
        except ValueError:
            return jsonify({"error": "Invalid client timezone offset value"}), 400

    effective_evtx_max_records = None
    if evtx_max_records_per_file:
        if not evtx_max_records_per_file.isdigit():
            return jsonify({"error": "Event Viewer scan depth must be numeric"}), 400
        parsed_evtx_depth = int(evtx_max_records_per_file)
        if parsed_evtx_depth < 1000 or parsed_evtx_depth > 500000:
            return jsonify({"error": "Event Viewer scan depth must be between 1000 and 500000"}), 400
        effective_evtx_max_records = parsed_evtx_depth
        
    if file and file.filename.endswith('.zip'):
        # Create a temporary directory for extraction
        temp_dir = tempfile.mkdtemp(prefix=f"darthawk_{selected_module}_")
        zip_path = os.path.join(temp_dir, file.filename)
        file.save(zip_path)
        
        extracted_files = []
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
                extracted_files = zip_ref.namelist()

            bundle_timezone, bundle_timezone_name = resolve_bundle_timezone(temp_dir)
            effective_flow_filter_start_dt = to_bundle_local_datetime(
                flow_filter_start_dt,
                client_timezone_offset_minutes,
                bundle_timezone,
            )
            effective_flow_filter_end_dt = to_bundle_local_datetime(
                flow_filter_end_dt,
                client_timezone_offset_minutes,
                bundle_timezone,
            )
            effective_srv_flow_start_dt = to_bundle_local_datetime(
                srv_flow_start_dt,
                client_timezone_offset_minutes,
                bundle_timezone,
            )
            effective_srv_flow_end_dt = to_bundle_local_datetime(
                srv_flow_end_dt,
                client_timezone_offset_minutes,
                bundle_timezone,
            )
                
            # --- BEGIN CUSTOM ANALYSIS LOGIC ---
            # Extend this block with actual log parsing scripts
            # e.g., if selected_module == 'VPN': parse_vpn_stats(temp_dir)
            
            if concise_zta_check_output or cached_config_search_only_output or selected_module == 'Duo Desktop':
                mock_report = ""
            else:
                mock_report = f"[+] Payload received: {file.filename}\n"

            srv_flow_candidates_payload = []
            srv_selected_identifier_trace_payload = []
            duo_posture_flow_summary_payload = None
            event_viewer_filtered_download_text = ""
            event_viewer_filtered_download_filename = "event_viewer_filtered_events.csv"
            event_viewer_summary_payload = None
            tnd_summary_payload = None
            user_pause_summary_payload = None

            org_id_results = extract_org_ids_from_enrollments(temp_dir)
            if selected_module == 'ZTA' and not cached_config_search_only_output and not concise_zta_check_output:
                if org_id_results["org_ids"]:
                    mock_report += "\n[ZTA Enrollment]\n"
                    if len(org_id_results["org_ids"]) == 1:
                        mock_report += f"  - This DART bundle is using ORG ID: {org_id_results['org_ids'][0]}\n"
                    else:
                        mock_report += "  - This DART bundle contains these ORG IDs:\n"
                        for org_id in org_id_results["org_ids"]:
                            mock_report += f"    * {org_id}\n"

                if org_id_results["user_ids"]:
                    if "\n[ZTA Enrollment]\n" not in mock_report:
                        mock_report += "\n[ZTA Enrollment]\n"
                    if len(org_id_results["user_ids"]) == 1:
                        mock_report += f"  - ZTA Enrollment User ID: {org_id_results['user_ids'][0]}\n"
                    else:
                        mock_report += "  - ZTA Enrollment User IDs:\n"
                        for user_id in org_id_results["user_ids"]:
                            mock_report += f"    * {user_id}\n"
                elif org_id_results["numeric_user_ids"]:
                    if "\n[ZTA Enrollment]\n" not in mock_report:
                        mock_report += "\n[ZTA Enrollment]\n"
                    if len(org_id_results["numeric_user_ids"]) == 1:
                        mock_report += f"  - ZTA Enrollment User ID: {org_id_results['numeric_user_ids'][0]}\n"
                    else:
                        mock_report += "  - ZTA Enrollment User IDs:\n"
                        for user_id in org_id_results["numeric_user_ids"]:
                            mock_report += f"    * {user_id}\n"

                if org_id_results["enrollment_methods"]:
                    if "\n[ZTA Enrollment]\n" not in mock_report:
                        mock_report += "\n[ZTA Enrollment]\n"
                    if len(org_id_results["enrollment_methods"]) == 1:
                        mock_report += f"  - ZTA Enrollment Method: {org_id_results['enrollment_methods'][0]}\n"
                    else:
                        mock_report += "  - ZTA Enrollment Methods:\n"
                        for enrollment_method in org_id_results["enrollment_methods"]:
                            mock_report += f"    * {enrollment_method}\n"

                if org_id_results["enrollment_times"]:
                    if "\n[ZTA Enrollment]\n" not in mock_report:
                        mock_report += "\n[ZTA Enrollment]\n"
                    if len(org_id_results["enrollment_times"]) == 1:
                        mock_report += f"  - ZTA Enrollment Time: {org_id_results['enrollment_times'][0]}\n"
                    else:
                        mock_report += "  - ZTA Enrollment Times:\n"
                        for enrollment_time in org_id_results["enrollment_times"]:
                            mock_report += f"    * {enrollment_time}\n"

                if org_id_results["warnings"] and not concise_include_exclude_output:
                    mock_report += "\n[ORG ID Parse Warnings]\n"
                    for warning in org_id_results["warnings"]:
                        mock_report += f"  - {warning}\n"

            enrollment_flow_payload = None
            if (
                selected_module == 'ZTA'
                and zta_access_mode == 'SPA'
                and spa_check_option == 'Check Enrollment Errors'
            ):
                if spa_enrollment_error_type == 'Cert':
                    cert_choice_files = find_cert_enrollment_choice_json_files(
                        temp_dir,
                        known_org_ids=org_id_results.get("org_ids", []),
                    )

                    cert_trace = extract_cert_auto_enrollment_trace(temp_dir)
                    cert_attempts = cert_trace.get("attempts") or []

                    if cert_attempts:
                        enrollment_flow_payload = {
                            "auth_method": "Cert",
                            "identifier": cert_attempts[-1].get("identifier", ""),
                            "attempts": [
                                {
                                    "index": idx,
                                    "identifier": attempt.get("identifier", ""),
                                    "trace_lines": attempt.get("trace_lines", []),
                                }
                                for idx, attempt in enumerate(cert_attempts, start=1)
                            ],
                        }

                    if cert_choice_files:
                        mock_report += "\n[Enrollment Choice JSON - Cert]\n"
                        mock_report += render_json_files_for_report(cert_choice_files, temp_dir)
                        mock_report += "\n"

                    if cert_attempts:
                        mock_report += "\n"
                        mock_report += f"Total Enrollment Attempts: {len(cert_attempts)}\n\n"
                        for attempt_index, attempt in enumerate(cert_attempts, start=1):
                            mock_report += f"Enrollment Attempt {attempt_index}\n"
                            mock_report += "-------------------\n"
                            for trace_line in attempt.get("trace_lines", []):
                                mock_report += f"{trace_line}\n"
                            if attempt_index < len(cert_attempts):
                                mock_report += "\n"

                    if not cert_choice_files and not cert_attempts:
                        mock_report += "\nNo matching logs found.\n"
                else:
                    saml_trace = extract_saml_auto_enrollment_trace(temp_dir)
                    saml_attempts = saml_trace.get("attempts") or []

                    if saml_attempts:
                        enrollment_flow_payload = {
                            "auth_method": "SAML",
                            "identifier": saml_attempts[-1].get("identifier", ""),
                            "attempts": [
                                {
                                    "index": idx,
                                    "identifier": attempt.get("identifier", ""),
                                    "trace_lines": attempt.get("trace_lines", []),
                                }
                                for idx, attempt in enumerate(saml_attempts, start=1)
                            ],
                        }

                    if saml_attempts:
                        mock_report += "\n"
                        mock_report += f"Total Enrollment Attempts: {len(saml_attempts)}\n\n"
                        for attempt_index, attempt in enumerate(saml_attempts, start=1):
                            mock_report += f"Enrollment Attempt {attempt_index}\n"
                            mock_report += "-------------------\n"
                            for trace_line in attempt.get("trace_lines", []):
                                mock_report += f"{trace_line}\n"
                            if attempt_index < len(saml_attempts):
                                mock_report += "\n"
                    else:
                        mock_report += "\nNo matching logs found.\n"

            if (
                selected_module == 'ZTA'
                and zta_access_mode == 'SPA'
                and spa_check_option == 'Check Configuration Sync'
            ):
                config_sync_context = collect_configuration_sync_error_context(temp_dir)
                config_sync_stats = config_sync_context.get("stats", {})
                config_sync_entries = config_sync_context.get("entries", [])
                stats_notifications = config_sync_context.get("stats_notifications", [])
                schedule_snapshots = config_sync_context.get("schedule_snapshots", [])

                timeframe_start_text = format_bundle_local_timestamp(
                    config_sync_context.get("timeframe_start"),
                    bundle_timezone,
                    bundle_timezone_name,
                ) or "Unknown"
                timeframe_end_text = format_bundle_local_timestamp(
                    config_sync_context.get("timeframe_end"),
                    bundle_timezone,
                    bundle_timezone_name,
                ) or "Unknown"

                def epoch_to_bundle_local_text(epoch_text):
                    raw = str(epoch_text or "").strip()
                    if not raw:
                        return "Unknown"
                    try:
                        epoch_value = int(raw)
                        dt_value = datetime.fromtimestamp(epoch_value, tz=bundle_timezone)
                        return format_bundle_local_timestamp(
                            dt_value,
                            bundle_timezone,
                            bundle_timezone_name,
                        ) or "Unknown"
                    except ValueError:
                        if raw.upper() == "N/A":
                            return "Unknown"

                        text_dt_formats = [
                            "%a %b %d %H:%M:%S %Y",
                            "%Y-%m-%d %H:%M:%S",
                            "%Y-%m-%d %H:%M:%S.%f",
                        ]
                        for text_format in text_dt_formats:
                            try:
                                parsed_text_dt = datetime.strptime(raw, text_format)
                                parsed_text_dt = parsed_text_dt.replace(tzinfo=bundle_timezone)
                                return format_bundle_local_timestamp(
                                    parsed_text_dt,
                                    bundle_timezone,
                                    bundle_timezone_name,
                                ) or raw
                            except ValueError:
                                continue

                        return raw

                latest_schedule_snapshot = schedule_snapshots[-1] if schedule_snapshots else {}
                last_sync_attempt_local = epoch_to_bundle_local_text(
                    latest_schedule_snapshot.get("last_sync_attempt_time")
                )
                last_sync_response_local = epoch_to_bundle_local_text(
                    latest_schedule_snapshot.get("last_sync_response_time")
                )
                next_sync_local = epoch_to_bundle_local_text(
                    latest_schedule_snapshot.get("next_sync_tp")
                )
                interval_seconds_text = (
                    str(latest_schedule_snapshot.get("interval_seconds"))
                    if latest_schedule_snapshot.get("interval_seconds")
                    else "Unknown"
                )

                enrollment_ids = config_sync_stats.get("enrollment_ids", [])
                enrollment_ids_text = ", ".join(enrollment_ids) if enrollment_ids else "Unknown"

                merged_items = []
                for entry in config_sync_entries:
                    merged_items.append(
                        {
                            "kind": "configsync",
                            "path": entry["path"],
                            "line_number": entry["line_number"],
                            "timestamp": entry.get("timestamp"),
                            "timestamp_text": entry.get("timestamp_text") or "Unknown",
                            "line": entry["line"],
                        }
                    )
                for notification in stats_notifications:
                    merged_items.append(
                        {
                            "kind": "onstats",
                            "path": notification["path"],
                            "line_number": notification["line_number"],
                            "timestamp": notification.get("timestamp"),
                            "timestamp_text": notification.get("timestamp_text") or "Unknown",
                            "raw_lines": notification.get("raw_lines", []),
                        }
                    )

                merged_items.sort(
                    key=lambda item: (
                        item["timestamp"] is None,
                        item["timestamp"] or datetime.max,
                        item["path"],
                        item["line_number"],
                    )
                )

                request_start_pattern = re.compile(
                    r"sent\s+config\s+sync\s+request\s+for\s+enrollment",
                    re.IGNORECASE,
                )
                success_response_pattern = re.compile(
                    r"config\s+sync\s+was\s+successful",
                    re.IGNORECASE,
                )
                # A config sync attempt begins at the InitSync "Initiated POST HTTP
                # request" line. Older bundles that lack that line fall back to the
                # "sent config sync request" line as the attempt boundary.
                init_boundary_pattern = re.compile(
                    r"Initiated\s+POST\s+HTTP\s+request", re.IGNORECASE
                )
                has_init_boundary = any(
                    item.get("kind") == "configsync"
                    and init_boundary_pattern.search(str(item.get("line", "")))
                    for item in merged_items
                )
                attempt_boundary_pattern = (
                    init_boundary_pattern if has_init_boundary else request_start_pattern
                )
                attempt_groups = []
                current_group = []
                for item in merged_items:
                    is_attempt_start = (
                        item.get("kind") == "configsync"
                        and attempt_boundary_pattern.search(str(item.get("line", ""))) is not None
                    )
                    if is_attempt_start and current_group:
                        attempt_groups.append(current_group)
                        current_group = []
                    current_group.append(item)
                if current_group:
                    attempt_groups.append(current_group)

                def count_requests_and_success(items):
                    sent_count = 0
                    success_count = 0
                    for item in items:
                        if item.get("kind") != "configsync":
                            continue
                        line_text = str(item.get("line", ""))
                        if request_start_pattern.search(line_text):
                            sent_count += 1
                        if success_response_pattern.search(line_text):
                            success_count += 1
                    return sent_count, success_count

                sent_requests_total, sync_success_total = count_requests_and_success(merged_items)

                time_range_display = f"{timeframe_start_text} -> {timeframe_end_text}"
                start_match = re.match(r"^(.*\d{2}:\d{2}:\d{2})\s(.+ Local Time)$", timeframe_start_text)
                end_match = re.match(r"^(.*\d{2}:\d{2}:\d{2})\s(.+ Local Time)$", timeframe_end_text)
                if start_match and end_match:
                    start_time_text, start_label = start_match.groups()
                    end_time_text, end_label = end_match.groups()
                    if start_label == end_label:
                        time_range_display = f"{start_time_text} -> {end_time_text} {start_label}"

                mock_report += "\n[Configuration Sync]\n"
                mock_report += f"  - Time Range: {time_range_display}\n"
                mock_report += f"  - Enrollment IDs: {enrollment_ids_text}\n"

                mock_report += "\n[Config Sync Stats]\n"
                mock_report += f"  - Sent Config Sync Requests: {sent_requests_total}\n"
                mock_report += f"  - Successful Sync Responses: {sync_success_total}\n"
                if len(attempt_groups) > 1:
                    for attempt_index, attempt_items in enumerate(attempt_groups, start=1):
                        attempt_sent_count, attempt_success_count = count_requests_and_success(attempt_items)
                        mock_report += (
                            f"  - Attempt {attempt_index} Sent Config Sync Requests: "
                            f"{attempt_sent_count}\n"
                        )
                        mock_report += (
                            f"  - Attempt {attempt_index} Successful Sync Responses: "
                            f"{attempt_success_count}\n"
                        )

                mock_report += "\n[Config Sync Scheduler Stats]\n"
                mock_report += f"  - Last Sync Attempt Time: {last_sync_attempt_local}\n"
                mock_report += f"  - Last Sync Response Time: {last_sync_response_local}\n"
                mock_report += f"  - Interval Seconds: {interval_seconds_text}\n"
                mock_report += f"  - Next Sync Time: {next_sync_local}\n"

                mock_report += "\n"
                if merged_items:
                    multiple_attempts = len(attempt_groups) > 1
                    for attempt_index, attempt_items in enumerate(attempt_groups, start=1):
                        if multiple_attempts:
                            mock_report += f"[Config Sync Attempt {attempt_index}]\n\n"
                        for item in attempt_items:
                            relative_path = os.path.relpath(item["path"], temp_dir)
                            mock_report += (
                                f"{relative_path}:L{item['line_number']} "
                                f"[{item['timestamp_text']}]\n"
                            )
                            if item["kind"] == "onstats":
                                for raw_line in item.get("raw_lines", []):
                                    mock_report += f"{raw_line}\n"
                            else:
                                mock_report += f"{item['line']}\n"
                            mock_report += "\n"
                else:
                    mock_report += "No matching logs found.\n"

                # Classification helpers for clickable success/failure navigation.
                config_sync_success_pattern = re.compile(
                    r"config\s+sync\s+was\s+successful", re.IGNORECASE
                )
                config_sync_status_pattern = re.compile(
                    r"(?:http_status|statuscode|status)\s*[:=]\s*([0-9]{3})", re.IGNORECASE
                )
                config_sync_failure_pattern = re.compile(
                    r"\b(error|failed|failure|exception|timeout|timed\s*out|unreachable|"
                    r"not\s+reachable|forbidden|unauthorized|refused|reset|denied|"
                    r"unable\s+to\s+connect|could\s+not\s+connect|cannot\s+connect)\b",
                    re.IGNORECASE,
                )
                config_sync_url_pattern = re.compile(
                    r"(?:configSyncUrl=|URL:\s*)(https?://[^\s;,)]+|[^\s,]+)",
                    re.IGNORECASE,
                )

                def classify_config_sync_text(text_value):
                    text_str = str(text_value or "")
                    lowered = text_str.lower()
                    if (
                        config_sync_success_pattern.search(text_str)
                        or "client already has the latest config" in lowered
                        or "http_status:304" in lowered
                    ):
                        return ("success", "Sync successful")
                    status_match = config_sync_status_pattern.search(text_str)
                    if status_match:
                        try:
                            code = int(status_match.group(1))
                            if code >= 400:
                                return ("failure", f"HTTP {code}")
                        except ValueError:
                            pass
                    if config_sync_failure_pattern.search(text_str):
                        if "unreachable" in lowered or "not reachable" in lowered:
                            return ("failure", "Server unreachable")
                        if "timeout" in lowered or "timed out" in lowered:
                            return ("failure", "Request timed out")
                        if "refused" in lowered:
                            return ("failure", "Connection refused")
                        if "reset" in lowered:
                            return ("failure", "Connection reset")
                        if "forbidden" in lowered or "unauthorized" in lowered or "denied" in lowered:
                            return ("failure", "Access denied")
                        return ("failure", "Error in response")
                    return ("info", "")

                # Structured payload powering the visual Configuration Sync panel.
                config_sync_multiple_attempts = len(attempt_groups) > 1
                config_sync_attempts_payload = []
                config_sync_detected_url = ""
                config_sync_line_seq = 0
                for attempt_index, attempt_items in enumerate(attempt_groups, start=1):
                    attempt_sent, attempt_success = count_requests_and_success(attempt_items)
                    attempt_lines = []

                    def make_config_sync_line(location_value, timestamp_value, text_value):
                        nonlocal config_sync_line_seq, config_sync_detected_url
                        config_sync_line_seq += 1
                        if not config_sync_detected_url:
                            url_match = config_sync_url_pattern.search(str(text_value or ""))
                            if url_match:
                                config_sync_detected_url = (
                                    url_match.group(1).strip().rstrip(".,;\"'")
                                )
                        line_type, line_reason = classify_config_sync_text(text_value)
                        return {
                            "id": f"cs-line-{config_sync_line_seq}",
                            "location": location_value,
                            "timestamp": timestamp_value,
                            "text": text_value,
                            "type": line_type,
                            "reason": line_reason,
                        }

                    for item in attempt_items:
                        relative_path = os.path.relpath(item["path"], temp_dir)
                        location = f"{relative_path}:L{item['line_number']}"
                        if item["kind"] == "onstats":
                            for raw_line in item.get("raw_lines", []):
                                attempt_lines.append(
                                    make_config_sync_line(
                                        location, item["timestamp_text"], raw_line
                                    )
                                )
                        else:
                            attempt_lines.append(
                                make_config_sync_line(
                                    location, item["timestamp_text"], item["line"]
                                )
                            )
                    config_sync_attempts_payload.append(
                        {
                            "index": attempt_index,
                            "sent": attempt_sent,
                            "success": attempt_success,
                            "lines": attempt_lines,
                        }
                    )

                if sent_requests_total == 0:
                    config_sync_verdict = "none"
                elif sync_success_total >= sent_requests_total:
                    config_sync_verdict = "healthy"
                elif sync_success_total > 0:
                    config_sync_verdict = "partial"
                else:
                    config_sync_verdict = "failed"

                config_sync_raw_lines = []
                for attempt in config_sync_attempts_payload:
                    if config_sync_multiple_attempts:
                        config_sync_raw_lines.append(f"[Config Sync Attempt {attempt['index']}]")
                    for line_item in attempt["lines"]:
                        config_sync_raw_lines.append(
                            f"{line_item['location']} [{line_item['timestamp']}]"
                        )
                        config_sync_raw_lines.append(line_item["text"])
                config_sync_raw_text = "\n".join(config_sync_raw_lines)

                config_sync_summary_payload = {
                    "found": bool(merged_items),
                    "verdict": config_sync_verdict,
                    "timeframe_start": timeframe_start_text,
                    "timeframe_end": timeframe_end_text,
                    "time_range_display": time_range_display,
                    "enrollment_ids": enrollment_ids,
                    "config_sync_url": config_sync_detected_url,
                    "sent_requests": sent_requests_total,
                    "success_responses": sync_success_total,
                    "multiple_attempts": config_sync_multiple_attempts,
                    "scheduler": {
                        "last_sync_attempt": last_sync_attempt_local,
                        "last_sync_response": last_sync_response_local,
                        "interval_seconds": interval_seconds_text,
                        "next_sync": next_sync_local,
                    },
                    "attempts": config_sync_attempts_payload,
                    "raw_text": config_sync_raw_text,
                    "download_filename": "configuration_sync_analysis.log",
                }

            if (
                selected_module == 'ZTA'
                and zta_access_mode == 'SPA'
                and spa_check_option == 'Check Server Connectivity Errors'
            ):
                proxy_context = collect_proxy_connectivity_transition_context(temp_dir)
                proxy_transition_lines = proxy_context.get("lines", []) if proxy_context.get("found") else []
                connectivity_download_categories = []

                def build_sc_download_payload(
                    category_id,
                    label,
                    entries,
                    custom_download_text=None,
                    custom_hit_count=None,
                ):
                    download_lines = []
                    if custom_download_text is None:
                        for entry in entries:
                            relative_path = os.path.relpath(entry['path'], temp_dir)
                            download_lines.append(
                                f"{relative_path}:L{entry['line_number']} [{entry['timestamp_text']}]"
                            )
                            download_lines.append(entry['line'])
                        download_text = "\n".join(download_lines)
                    else:
                        download_text = str(custom_download_text)

                    connectivity_download_categories.append(
                        {
                            "id": category_id,
                            "label": label,
                            "hit_count": custom_hit_count if custom_hit_count is not None else len(entries),
                            "download_filename": f"server_connectivity_{category_id}.log",
                            "download_text": download_text,
                        }
                    )

                if proxy_context.get("found"):
                    ok_entry = proxy_context["ok_entry"]
                    unreachable_entry = proxy_context["unreachable_entry"]
                    redirected_flow_line_pattern = re.compile(
                        r"new\s+redirected\s+flow:\s*(?:UDP|TCP)\s+destination",
                        re.IGNORECASE,
                    )
                    redirected_destination_pattern = re.compile(
                        r"destination\s*(?:=|:)?\s*([^\s,;]+)",
                        re.IGNORECASE,
                    )
                    redirected_src_port_pattern = re.compile(
                        r"(?:srcPort|flowSrcPort)\s*=\s*(\d+)",
                        re.IGNORECASE,
                    )

                    redirected_destinations = []
                    redirected_destinations_seen = set()
                    redirected_flow_entries_by_destination = {}
                    redirected_src_ports_by_destination = {}

                    def sanitize_category_id(text):
                        return re.sub(r"[^a-z0-9]+", "_", str(text or "").strip().lower()).strip("_")

                    for entry in proxy_transition_lines:
                        line_text = str(entry.get("line", ""))
                        if not redirected_flow_line_pattern.search(line_text):
                            continue
                        destination_match = redirected_destination_pattern.search(line_text)
                        if not destination_match:
                            continue
                        destination_value = destination_match.group(1).strip()
                        if not destination_value:
                            continue
                        normalized_destination_value = destination_value.lower()
                        if normalized_destination_value in redirected_destinations_seen:
                            destination_key = next(
                                (
                                    key
                                    for key in redirected_destinations
                                    if key.lower() == normalized_destination_value
                                ),
                                destination_value,
                            )
                        else:
                            redirected_destinations_seen.add(normalized_destination_value)
                            redirected_destinations.append(destination_value)
                            destination_key = destination_value

                        redirected_flow_entries_by_destination.setdefault(destination_key, [])
                        redirected_src_ports_by_destination.setdefault(destination_key, set())

                        src_port_match = redirected_src_port_pattern.search(line_text)
                        if src_port_match:
                            redirected_src_ports_by_destination[destination_key].add(src_port_match.group(1))

                    for entry in proxy_transition_lines:
                        line_text = str(entry.get("line", ""))
                        if not redirected_flow_line_pattern.search(line_text):
                            continue
                        destination_match = redirected_destination_pattern.search(line_text)
                        if not destination_match:
                            continue
                        destination_value = destination_match.group(1).strip()
                        if not destination_value:
                            continue

                        destination_key = next(
                            (
                                key
                                for key in redirected_destinations
                                if key.lower() == destination_value.lower()
                            ),
                            destination_value,
                        )

                        redirected_flow_entries_by_destination.setdefault(destination_key, []).append(entry)

                    for destination_value in redirected_destinations:
                        src_ports = sorted(redirected_src_ports_by_destination.get(destination_value, set()))
                        if not src_ports:
                            continue

                        src_port_patterns = [
                            re.compile(
                                rf"(?:(?:srcPort|flowSrcPort)\s*=\s*{re.escape(src_port)}\b|(?:tcp|udp):{re.escape(src_port)}__)",
                                re.IGNORECASE,
                            )
                            for src_port in src_ports
                        ]

                        expanded_entries = []
                        expanded_entry_keys = set()
                        for entry in proxy_transition_lines:
                            line_text = str(entry.get("line", ""))
                            if not any(pattern.search(line_text) for pattern in src_port_patterns):
                                continue
                            entry_key = (entry.get("path"), entry.get("line_number"))
                            if entry_key in expanded_entry_keys:
                                continue
                            expanded_entry_keys.add(entry_key)
                            expanded_entries.append(entry)

                        redirected_flow_entries_by_destination[destination_value] = expanded_entries

                    mock_report += "TCP or UDP Flows within that time range:\n"
                    if redirected_destinations:
                        for destination_value in redirected_destinations:
                            source_ports = sorted(redirected_src_ports_by_destination.get(destination_value, set()))
                            destination_entries = redirected_flow_entries_by_destination.get(destination_value, [])
                            destination_start_timestamp = "Unknown"
                            destination_end_timestamp = "Unknown"

                            if destination_entries:
                                first_entry = destination_entries[0]
                                last_entry = destination_entries[-1]
                                destination_start_timestamp = first_entry.get("timestamp_text") or "Unknown"
                                destination_end_timestamp = last_entry.get("timestamp_text") or "Unknown"

                            destination_timeframe_text = (
                                destination_start_timestamp
                                if destination_start_timestamp == destination_end_timestamp
                                else f"{destination_start_timestamp} -> {destination_end_timestamp}"
                            )

                            if source_ports:
                                mock_report += (
                                    f"- timeframe: {destination_timeframe_text} | {destination_value} "
                                    f"| source ports: {', '.join(source_ports)}\n"
                                )
                            else:
                                mock_report += f"- timeframe: {destination_timeframe_text} | {destination_value}\n"
                    else:
                        mock_report += "- None found\n"

                    for entry in proxy_transition_lines:
                        mock_report += f"{entry['line']}\n"

                    build_sc_download_payload(
                        "proxy_connectivity_transition",
                        "Proxy Connectivity",
                        proxy_transition_lines,
                    )

                    for destination_value in redirected_destinations:
                        destination_source_ports = sorted(redirected_src_ports_by_destination.get(destination_value, set()))

                        for src_port in destination_source_ports:
                            src_port_pattern = re.compile(
                                rf"(?:(?:srcPort|flowSrcPort)\s*=\s*{re.escape(src_port)}\b|(?:tcp|udp):{re.escape(src_port)}__)",
                                re.IGNORECASE,
                            )
                            src_port_entries = []
                            src_port_entry_keys = set()
                            for entry in proxy_transition_lines:
                                line_text = str(entry.get("line", ""))
                                if not src_port_pattern.search(line_text):
                                    continue
                                entry_key = (entry.get("path"), entry.get("line_number"))
                                if entry_key in src_port_entry_keys:
                                    continue
                                src_port_entry_keys.add(entry_key)
                                src_port_entries.append(entry)

                            if not src_port_entries:
                                continue

                            src_port_download_lines = [
                                f"[Destination: {destination_value} | Source Port: {src_port}]"
                            ]
                            for entry in src_port_entries:
                                relative_path = os.path.relpath(entry['path'], temp_dir)
                                src_port_download_lines.append(
                                    f"{relative_path}:L{entry['line_number']} [{entry['timestamp_text']}]"
                                )
                                src_port_download_lines.append(entry['line'])

                            build_sc_download_payload(
                                f"spa_flow_{sanitize_category_id(destination_value)}_src_{src_port}",
                                f"{destination_value} | srcPort {src_port}",
                                src_port_entries,
                                custom_download_text="\n".join(src_port_download_lines),
                                custom_hit_count=len(src_port_entries),
                            )

                    raw_timeframe_start = ok_entry.get("timestamp")
                    raw_timeframe_end = unreachable_entry.get("timestamp")

                    def build_entries_download_text(entries):
                        lines = []
                        for entry in entries:
                            relative_path = os.path.relpath(entry['path'], temp_dir)
                            lines.append(
                                f"{relative_path}:L{entry['line_number']} [{entry['timestamp_text']}]"
                            )
                            lines.append(entry['line'])
                        return "\n".join(lines)

                    # ---- ProxyConfigPause status check ----
                    proxy_pause_item_pattern = re.compile(r"\{([^{}]*)\}")
                    proxy_pause_label_pattern = re.compile(r"labelStr=([^,}]+)")
                    proxy_pause_status_pattern = re.compile(r"statusStr=([^,}]+)")
                    proxy_pause_state_pattern = re.compile(r"\bstate=([^,}\s]+)")
                    proxy_pause_status_history = {}
                    proxy_pause_order = []
                    proxy_pause_entries = []
                    proxy_pause_timestamp = "Unknown"
                    for entry in proxy_transition_lines:
                        line_text = str(entry.get("line", ""))
                        if "updateAdvancedProxyConfigPauseData" not in line_text:
                            continue
                        proxy_pause_entries.append(entry)
                        if "items=[" not in line_text:
                            continue
                        items_segment = line_text.split("items=[", 1)[1]
                        for item_block in proxy_pause_item_pattern.findall(items_segment):
                            label_match = proxy_pause_label_pattern.search(item_block)
                            if not label_match:
                                continue
                            label_value = label_match.group(1).strip()
                            status_match = proxy_pause_status_pattern.search(item_block)
                            state_match = proxy_pause_state_pattern.search(item_block)
                            status_value = (
                                status_match.group(1).strip()
                                if status_match
                                else (state_match.group(1).strip().title() if state_match else "Unknown")
                            )
                            key = label_value.lower()
                            if key not in proxy_pause_status_history:
                                proxy_pause_status_history[key] = {"label": label_value, "states": []}
                                proxy_pause_order.append(key)
                            states = proxy_pause_status_history[key]["states"]
                            if not states or states[-1].lower() != status_value.lower():
                                states.append(status_value)
                        ts = entry.get("timestamp_text")
                        if ts:
                            proxy_pause_timestamp = ts

                    proxy_pause_configs = []
                    for key in proxy_pause_order:
                        info = proxy_pause_status_history[key]
                        states = info["states"]
                        latest_status = states[-1] if states else "Unknown"
                        changed = len(states) > 1
                        proxy_pause_configs.append(
                            {
                                "label": info["label"],
                                "status": latest_status,
                                "changed": changed,
                                "transition": " -> ".join(states) if changed else "",
                            }
                        )

                    proxy_config_pause_summary = {
                        "found": bool(proxy_pause_configs),
                        "timestamp": proxy_pause_timestamp,
                        "configs": proxy_pause_configs,
                        "all_active": bool(proxy_pause_configs)
                        and all(cfg["status"].lower() == "active" for cfg in proxy_pause_configs),
                        "status_changed": any(cfg["changed"] for cfg in proxy_pause_configs),
                    }
                    if proxy_pause_entries:
                        proxy_config_pause_summary["download_text"] = build_entries_download_text(proxy_pause_entries)
                        proxy_config_pause_summary["download_filename"] = "server_connectivity_proxy_config_pause_status.log"

                    # ---- Network Change Detection status check ----
                    network_change_subscriber_pattern = re.compile(
                        r"subscriber=(\S+)\s+timeout=(\d+)",
                        re.IGNORECASE,
                    )
                    on_network_change_pattern = re.compile(
                        r"OnNetworkChange\(\)\s*(.*?)\s*$",
                        re.IGNORECASE,
                    )
                    network_change_entries = []
                    network_change_subscribers = []
                    network_change_seen = set()
                    network_change_events = []
                    network_change_events_seen = set()
                    network_change_detected = False
                    network_change_timestamp = "Unknown"
                    for entry in proxy_transition_lines:
                        line_text = str(entry.get("line", ""))
                        if "NetworkChangeService" not in line_text:
                            continue
                        network_change_entries.append(entry)
                        is_change_event = (
                            "OnNetworkChange" in line_text
                            or "due to network change" in line_text
                            or "global debounce timer" in line_text
                            or "debounce timer expired" in line_text
                        )
                        if is_change_event:
                            network_change_detected = True
                            network_change_timestamp = entry.get("timestamp_text") or network_change_timestamp
                        change_match = on_network_change_pattern.search(line_text)
                        if change_match:
                            event_text = change_match.group(1).strip()
                            if event_text and event_text.lower() not in network_change_events_seen:
                                network_change_events_seen.add(event_text.lower())
                                network_change_events.append(event_text)
                        sub_match = network_change_subscriber_pattern.search(line_text)
                        if sub_match:
                            sub_name = sub_match.group(1).strip()
                            sub_timeout = sub_match.group(2).strip()
                            sub_key = (sub_name.lower(), sub_timeout)
                            if sub_key not in network_change_seen:
                                network_change_seen.add(sub_key)
                                network_change_subscribers.append({"name": sub_name, "timeout": sub_timeout})

                    network_change_summary = {
                        "found": bool(network_change_entries),
                        "detected": network_change_detected,
                        "timestamp": network_change_timestamp,
                        "subscribers": network_change_subscribers,
                        "events": network_change_events,
                    }
                    if network_change_entries:
                        network_change_summary["download_text"] = build_entries_download_text(network_change_entries)
                        network_change_summary["download_filename"] = "server_connectivity_network_change_detection.log"

                    connectivity_context = {
                        "table_summary": {
                            "timeframe_start": format_bundle_local_timestamp(
                                raw_timeframe_start,
                                bundle_timezone,
                                bundle_timezone_name,
                            ) or "Unknown",
                            "timeframe_end": format_bundle_local_timestamp(
                                raw_timeframe_end,
                                bundle_timezone,
                                bundle_timezone_name,
                            ) or "Unknown",
                            "categories": connectivity_download_categories,
                            "proxy_config_pause": proxy_config_pause_summary,
                            "network_change": network_change_summary,
                        }
                    }
                else:
                    mock_report += (
                        "  - No matching logs found.\n"
                    )
                    connectivity_context = {
                        "table_summary": {
                            "timeframe_start": "Unknown",
                            "timeframe_end": "Unknown",
                            "categories": [],
                            "proxy_config_pause": {"found": False, "configs": []},
                            "network_change": {"found": False, "detected": False, "subscribers": []},
                        }
                    }

            if (
                selected_module == 'ZTA'
                and zta_access_mode == 'SPA'
                and spa_check_option == 'Check Event Viewer Logs'
            ):
                evtx_scan = scan_evtx_channels(
                    temp_dir,
                    level_filter={"Critical", "Error", "Warning"},
                    max_records_per_file=effective_evtx_max_records or 200000,
                )
                mock_report += "\n[Event Viewer Analysis]\n"

                zta_log_paths = find_module_log_text_files(temp_dir, "Zero Trust Access")
                zta_primary_paths = [
                    path
                    for path in zta_log_paths
                    if os.path.basename(path).lower() == "zerotrustaccess.txt"
                ]
                zta_timeframe_sources = zta_primary_paths or zta_log_paths
                zta_timeframe_bounds = extract_log_time_window_bounds(zta_timeframe_sources)
                derived_evtx_time_start_dt = zta_timeframe_bounds.get("start_dt")
                derived_evtx_time_end_dt = zta_timeframe_bounds.get("end_dt")

                if derived_evtx_time_start_dt and derived_evtx_time_end_dt:
                    mock_report += (
                        "  - Derived Timeframe from ZeroTrustAccess.txt (DART local): "
                        f"{format_bundle_filter_datetime(derived_evtx_time_start_dt, bundle_timezone, bundle_timezone_name)}"
                        " to "
                        f"{format_bundle_filter_datetime(derived_evtx_time_end_dt, bundle_timezone, bundle_timezone_name)}\n"
                    )
                else:
                    mock_report += (
                        "  - Derived Timeframe from ZeroTrustAccess.txt (DART local): unavailable. "
                        "Showing all parsed Event Viewer entries.\n"
                    )

                files_by_channel = evtx_scan.get('files', {})
                app_count = len(files_by_channel.get('Application', []))
                sys_count = len(files_by_channel.get('System', []))
                zta_count = len(files_by_channel.get('ZTA', []))
                mock_report += (
                    f"  - EVTX Files Found: Application={app_count}, System={sys_count}, ZTA={zta_count}\n"
                )

                if evtx_scan.get('error'):
                    mock_report += f"  - {evtx_scan['error']}\n"
                else:
                    scanned_events = evtx_scan.get('events', [])
                    scanned_event_timestamps = [
                        event.get('timestamp')
                        for event in scanned_events
                        if event.get('timestamp') is not None
                    ]
                    available_event_start = min(scanned_event_timestamps) if scanned_event_timestamps else None
                    available_event_end = max(scanned_event_timestamps) if scanned_event_timestamps else None

                    if derived_evtx_time_start_dt and derived_evtx_time_end_dt:
                        events = [
                            event
                            for event in scanned_events
                            if (
                                event.get('timestamp') is not None
                                and derived_evtx_time_start_dt <= event.get('timestamp') <= derived_evtx_time_end_dt
                            )
                        ]
                    else:
                        events = [
                            event
                            for event in scanned_events
                            if event.get('timestamp') is not None
                        ]
                    mock_report += f"  - Parsed Warning/Error/Critical Events: {len(scanned_events)}\n"
                    mock_report += f"  - Events Within Timeframe: {len(events)}\n"
                    if available_event_start and available_event_end:
                        mock_report += (
                            "  - Available Event Time Range (DART local): "
                            f"{format_bundle_local_timestamp(available_event_start, bundle_timezone, bundle_timezone_name)}"
                            " to "
                            f"{format_bundle_local_timestamp(available_event_end, bundle_timezone, bundle_timezone_name)}\n"
                        )

                    if len(events) == 0 and len(scanned_events) > 0 and derived_evtx_time_start_dt and derived_evtx_time_end_dt:
                        mock_report += (
                            "  - NOTE: No events matched the ZeroTrustAccess.txt-derived timeframe.\n"
                        )
                        mock_report += (
                            "  - Showing parsed Warning/Error/Critical events outside that timeframe below.\n"
                        )

                    def resolve_event_viewer_bucket(event_item):
                        channel_text = str(event_item.get('channel', '')).strip().lower()
                        path_text = str(event_item.get('path', '')).strip().lower()
                        compact_channel = re.sub(r'[^a-z0-9]', '', channel_text)
                        compact_path = re.sub(r'[^a-z0-9]', '', path_text)
                        if 'application' in compact_channel:
                            return 'Application'
                        if 'system' in compact_channel:
                            return 'System'
                        if (
                            'zerotrustaccess' in compact_channel
                            or 'zta' in compact_channel
                            or 'zerotrustaccess' in compact_path
                            or 'zta' in compact_path
                        ):
                            return 'ZTA'
                        return 'ZTA' if 'zta' in compact_channel else 'System'

                    bucket_order = ['Application', 'System', 'ZTA']
                    severity_order = ['Error', 'Critical', 'Warning', 'Information', 'Verbose', 'Unknown']
                    display_events = list(events if events else scanned_events)

                    # ZTA fallback: if the timeframe-filtered set has no ZeroTrustAccess events,
                    # show ALL ZTA channel logs (any severity) instead of an empty ZTA section.
                    zta_fallback_used = False
                    zta_in_display = any(
                        resolve_event_viewer_bucket(event) == 'ZTA'
                        for event in display_events
                    )
                    if not zta_in_display and zta_count > 0:
                        zta_only_scan = scan_evtx_channels(
                            temp_dir,
                            level_filter=None,
                            max_records_per_file=effective_evtx_max_records or 200000,
                            channels={'ZTA'},
                        )
                        zta_only_events = zta_only_scan.get('events', [])
                        if zta_only_events:
                            display_events = display_events + zta_only_events
                            zta_fallback_used = True

                    grouped_events = {
                        bucket: {severity: [] for severity in severity_order}
                        for bucket in bucket_order
                    }

                    for event in display_events:
                        severity = str(event.get('level', '')).strip().title()
                        if severity not in severity_order:
                            severity = 'Unknown'
                        grouped_events[resolve_event_viewer_bucket(event)][severity].append(event)

                    full_download_lines = [
                        "[Event Viewer Filtered Events]",
                        (
                            "Derived Timeframe from ZeroTrustAccess.txt (DART local): "
                            f"{format_bundle_filter_datetime(derived_evtx_time_start_dt, bundle_timezone, bundle_timezone_name)}"
                            " to "
                            f"{format_bundle_filter_datetime(derived_evtx_time_end_dt, bundle_timezone, bundle_timezone_name)}"
                        ) if (derived_evtx_time_start_dt and derived_evtx_time_end_dt)
                        else "Derived Timeframe from ZeroTrustAccess.txt (DART local): unavailable (all parsed events shown)",
                        f"EVTX Files Found: Application={app_count}, System={sys_count}, ZTA={zta_count}",
                        f"Parsed Warning/Error/Critical Events: {len(scanned_events)}",
                        f"Events Within Timeframe: {len(events)}",
                        f"Events Shown In Output: {len(display_events)}",
                        "",
                    ]
                    if len(display_events) == 0:
                        if derived_evtx_time_start_dt and derived_evtx_time_end_dt:
                            full_download_lines.append("No events matched the ZeroTrustAccess.txt-derived timeframe.")
                        else:
                            full_download_lines.append("No timestamped Warning/Error/Critical events were found.")
                        full_download_lines.append("")
                    elif len(events) == 0 and derived_evtx_time_start_dt and derived_evtx_time_end_dt:
                        full_download_lines.append(
                            "No events matched the ZeroTrustAccess.txt-derived timeframe; showing parsed events outside that timeframe."
                        )
                        full_download_lines.append("")

                    for bucket in bucket_order:
                        full_download_lines.append(f"[{bucket}]")
                        for severity in severity_order:
                            severity_events = sorted(
                                grouped_events[bucket][severity],
                                key=lambda item: item['timestamp'] if item.get('timestamp') else datetime.min,
                                reverse=True,
                            )
                            full_download_lines.append(f"  - {severity}: {len(severity_events)}")
                        full_download_lines.append("")

                    flattened_events = []
                    for bucket in bucket_order:
                        for severity in severity_order:
                            severity_events = sorted(
                                grouped_events[bucket][severity],
                                key=lambda item: item['timestamp'] if item.get('timestamp') else datetime.min,
                                reverse=True,
                            )
                            for event in severity_events:
                                flattened_events.append((bucket, severity, event))

                    derived_timeframe_start_text = format_bundle_filter_datetime(
                        derived_evtx_time_start_dt,
                        bundle_timezone,
                        bundle_timezone_name,
                    ) if derived_evtx_time_start_dt and derived_evtx_time_end_dt else "unavailable"
                    derived_timeframe_end_text = format_bundle_filter_datetime(
                        derived_evtx_time_end_dt,
                        bundle_timezone,
                        bundle_timezone_name,
                    ) if derived_evtx_time_start_dt and derived_evtx_time_end_dt else "unavailable"

                    csv_buffer = io.StringIO()
                    csv_writer = csv.writer(csv_buffer)
                    csv_writer.writerow([
                        "Timestamp",
                        "Severity",
                        "Provider",
                        "EventID",
                        "Channel",
                        "Message",
                    ])

                    for bucket, severity, event in flattened_events:
                        message_text = str(event.get('message_preview') or '').replace('\n', ' ').replace('\r', ' ')
                        # Remove XML-style string wrappers to keep CSV message values clean.
                        message_text = (
                            message_text
                            .replace('&lt;string&gt;', '')
                            .replace('&lt;/string&gt;', '')
                            .replace('<string>', '')
                            .replace('</string>', '')
                            .strip()
                        )
                        csv_writer.writerow([
                            event.get('timestamp_text') or "Unknown",
                            severity,
                            event.get('provider') or "Unknown",
                            event.get('event_id') or 0,
                            bucket,
                            message_text,
                        ])

                    if not flattened_events:
                        csv_writer.writerow([
                            "",
                            "",
                            "",
                            "",
                            "",
                            "No Warning/Error/Critical events were found.",
                        ])

                    event_viewer_filtered_download_text = csv_buffer.getvalue()
                    event_viewer_filtered_download_filename = "event_viewer_filtered_events.csv"

                    def clean_event_message(raw_message):
                        text = str(raw_message or '')
                        text = (
                            text
                            .replace('&lt;string&gt;', '')
                            .replace('&lt;/string&gt;', '')
                            .replace('<string>', '')
                            .replace('</string>', '')
                        )
                        text = text.replace('\r\n', '\n').replace('\r', '\n')
                        return text.strip()

                    event_viewer_events_payload = []
                    event_viewer_seq = 0
                    for event in sorted(
                        display_events,
                        key=lambda item: item['timestamp'] if item.get('timestamp') else datetime.min,
                    ):
                        severity = str(event.get('level', '')).strip().title()
                        if severity not in severity_order:
                            continue
                        event_source_path = event.get('path')
                        if event_source_path:
                            try:
                                event_source_display = os.path.basename(event_source_path) or os.path.relpath(event_source_path, temp_dir)
                            except Exception:
                                event_source_display = str(event_source_path)
                        else:
                            event_source_display = "Unknown"
                        event_viewer_events_payload.append({
                            "id": f"ev-line-{event_viewer_seq}",
                            "timestamp": event.get('timestamp_text') or "Unknown",
                            "severity": severity,
                            "channel": resolve_event_viewer_bucket(event),
                            "provider": event.get('provider') or "Unknown",
                            "event_id": event.get('event_id') or 0,
                            "message": clean_event_message(event.get('message_preview')),
                            "source": event_source_display,
                        })
                        event_viewer_seq += 1

                    event_viewer_counts = {
                        bucket: {
                            severity: len(grouped_events[bucket][severity])
                            for severity in severity_order
                        }
                        for bucket in bucket_order
                    }

                    event_viewer_time_range_display = (
                        f"{derived_timeframe_start_text} to {derived_timeframe_end_text}"
                        if derived_evtx_time_start_dt and derived_evtx_time_end_dt
                        else "unavailable (all parsed events shown)"
                    )
                    event_viewer_available_range_display = (
                        f"{format_bundle_local_timestamp(available_event_start, bundle_timezone, bundle_timezone_name)}"
                        f" to {format_bundle_local_timestamp(available_event_end, bundle_timezone, bundle_timezone_name)}"
                        if available_event_start and available_event_end
                        else ""
                    )
                    event_viewer_note = ""
                    if len(events) == 0 and len(scanned_events) > 0 and derived_evtx_time_start_dt and derived_evtx_time_end_dt:
                        event_viewer_note = (
                            "No events matched the ZeroTrustAccess.txt-derived timeframe; "
                            "showing parsed Warning/Error/Critical events outside that timeframe."
                        )
                    if zta_fallback_used:
                        zta_fallback_msg = (
                            "No ZeroTrustAccess events matched the derived timeframe; "
                            "showing all ZeroTrustAccess channel logs (any severity) in the ZTA section."
                        )
                        event_viewer_note = (
                            f"{event_viewer_note} {zta_fallback_msg}".strip()
                            if event_viewer_note
                            else zta_fallback_msg
                        )

                    event_viewer_summary_payload = {
                        "found": len(event_viewer_events_payload) > 0,
                        "timeframe_start": derived_timeframe_start_text,
                        "timeframe_end": derived_timeframe_end_text,
                        "time_range_display": event_viewer_time_range_display,
                        "timeframe_available": bool(derived_evtx_time_start_dt and derived_evtx_time_end_dt),
                        "available_range_display": event_viewer_available_range_display,
                        "files": {
                            "application": app_count,
                            "system": sys_count,
                            "zta": zta_count,
                        },
                        "parsed_total": len(scanned_events),
                        "within_timeframe": len(events),
                        "shown": len(display_events),
                        "note": event_viewer_note,
                        "counts": event_viewer_counts,
                        "channel_order": list(bucket_order),
                        "severity_order": list(severity_order),
                        "events": event_viewer_events_payload,
                        "download_filename": event_viewer_filtered_download_filename,
                    }

                    if len(display_events) > 0:
                        mock_report += (
                            "\nResults are ready for download. "
                            "Please click the download link to see matching event details.\n"
                        )
                    else:
                        mock_report += (
                            "\nNo Warning/Error/Critical events were found to include in download output.\n"
                        )

                    for bucket in bucket_order:
                        mock_report += f"\n[{bucket}]\n"
                        for severity in severity_order:
                            severity_events = sorted(
                                grouped_events[bucket][severity],
                                key=lambda item: item['timestamp'] if item.get('timestamp') else datetime.min,
                                reverse=True,
                            )
                            mock_report += f"  - {severity}: {len(severity_events)}\n"

            if selected_module == 'ZTA':
                json_candidates = find_zta_cached_config_json_files(temp_dir)
                if not json_candidates:
                    if not concise_zta_check_output:
                        mock_report += "\nNo matching logs found.\n"
                else:
                    if (
                        not concise_include_exclude_output
                        and not concise_zta_check_output
                        and not cached_config_search_only_output
                    ):
                        mock_report += "\n[ZTA cached_config JSON files]\n"
                        for json_file in json_candidates:
                            relative_path = os.path.relpath(json_file, temp_dir)
                            mock_report += f"  - {relative_path}\n"

                    if (
                        not concise_include_exclude_output
                        and not concise_zta_check_output
                        and not cached_config_search_only_output
                    ):
                        extracted_values = []
                        parse_errors = []
                        for json_file in json_candidates:
                            try:
                                extracted_values.append(extract_zta_values_from_json(json_file, zta_access_mode))
                            except (json.JSONDecodeError, OSError) as exc:
                                parse_errors.append(f"{os.path.relpath(json_file, temp_dir)} -> {exc}")

                        ip_exclusions = sorted(set(
                            value
                            for result in extracted_values
                            for value in result["ip_exclusions"]
                        ))
                        fqdn_exclusions = sorted(set(
                            value
                            for result in extracted_values
                            for value in result["fqdn_exclusions"]
                        ))
                        other_exclusions = sorted(set(
                            value
                            for result in extracted_values
                            for value in result["other_exclusions"]
                        ))
                        section_matches = sum(result["matched_sections"] for result in extracted_values)

                        mock_report += f"\n[ZTA {zta_access_mode} Results]\n"
                        mock_report += f"  - Matched SPA/SIA sections: {section_matches}\n"

                        mock_report += "  - IP Exclusions:\n"
                        if ip_exclusions:
                            for value in ip_exclusions:
                                mock_report += f"    * {value}\n"
                        else:
                            mock_report += "    * None found\n"

                        mock_report += "  - FQDN Exclusions:\n"
                        if fqdn_exclusions:
                            for value in fqdn_exclusions:
                                mock_report += f"    * {value}\n"
                        else:
                            mock_report += "    * None found\n"

                        if other_exclusions:
                            mock_report += "  - Other Exclusion Entries:\n"
                            for value in other_exclusions:
                                mock_report += f"    * {value}\n"

                        if parse_errors:
                            mock_report += "\n[ZTA JSON Parse Warnings]\n"
                            for warning in parse_errors:
                                mock_report += f"  - {warning}\n"

                    if (
                        zta_access_mode in {'SPA', 'SIA'}
                        and spa_check_option == 'Check Inclusions or Exclusions'
                    ):
                        flow_plans = []
                        if spa_check_option == 'Check Inclusions or Exclusions':
                            # Interception should evaluate full resource config coverage across SPA and SIA.
                            flow_plans = [
                                ('SPA', 'spa_steering_config', False),
                                ('SIA', 'tia_steering_config', True),
                            ]
                        else:
                            flow_plans = [('SIA', 'tia_steering_config', True)]

                        flow_summaries = []
                        for flow_name, steering_config_id, use_dns_for_fqdn in flow_plans:
                            resource_results = []
                            resource_parse_errors = []
                            for json_file in json_candidates:
                                try:
                                    resource_results.append(
                                        extract_include_exclude_from_resource_configs(json_file, steering_config_id)
                                    )
                                except (json.JSONDecodeError, OSError) as exc:
                                    resource_parse_errors.append(
                                        f"{os.path.relpath(json_file, temp_dir)} -> {exc}"
                                    )

                            cidr_include = sorted(set(
                                value
                                for result in resource_results
                                for value in result["cidr_include"]
                            ))
                            cidr_exclude = sorted(set(
                                value
                                for result in resource_results
                                for value in result["cidr_exclude"]
                            ))
                            fqdn_include = sorted(set(
                                value
                                for result in resource_results
                                for value in result["fqdn_include"]
                            ))
                            fqdn_exclude = sorted(set(
                                value
                                for result in resource_results
                                for value in result["fqdn_exclude"]
                            ))
                            dns_include = sorted(set(
                                value
                                for result in resource_results
                                for value in result["dns_include"]
                            ))
                            dns_exclude = sorted(set(
                                value
                                for result in resource_results
                                for value in result["dns_exclude"]
                            ))

                            if use_dns_for_fqdn:
                                fqdn_include_rules = sorted(set(fqdn_include + dns_include))
                                fqdn_exclude_rules = sorted(set(fqdn_exclude + dns_exclude))
                            else:
                                fqdn_include_rules = fqdn_include
                                fqdn_exclude_rules = fqdn_exclude

                            flow_summaries.append(
                                {
                                    "flow": flow_name,
                                    "matched_configs": sum(
                                        result["matched_steering_config"] for result in resource_results
                                    ),
                                    "cidr_include": cidr_include,
                                    "cidr_exclude": cidr_exclude,
                                    "fqdn_include": fqdn_include,
                                    "fqdn_exclude": fqdn_exclude,
                                    "dns_include": dns_include,
                                    "dns_exclude": dns_exclude,
                                    "fqdn_include_rules": fqdn_include_rules,
                                    "fqdn_exclude_rules": fqdn_exclude_rules,
                                    "parse_errors": resource_parse_errors,
                                }
                            )

                        if spa_check_option == 'Check Inclusions or Exclusions' and not spa_target_value:
                            cached_config_dump = render_cached_config_files(json_candidates, temp_dir)
                            if cached_config_dump:
                                mock_report += "\n[Complete Cached Config]\n"
                                mock_report += cached_config_dump
                                mock_report += "\n"
                            else:
                                mock_report += "\nNo matching logs found.\n"
                        else:
                            for summary in flow_summaries:
                                evaluation = evaluate_spa_target_against_include_exclude(
                                    spa_target_value,
                                    summary['cidr_include'],
                                    summary['cidr_exclude'],
                                    summary['fqdn_include_rules'],
                                    summary['fqdn_exclude_rules'],
                                    summary['dns_include'],
                                    summary['dns_exclude'],
                                )

                                mock_report += f"\n[{summary['flow']} Include/Exclude Match Result]\n"
                                mock_report += f"  - Input Target: {evaluation['target']}\n"
                                mock_report += f"  - Input Type: {evaluation['type']}\n"
                                match_result = evaluation['classification']
                                if match_result == 'no include/exclude match':
                                    match_result = 'resource does not exist in cached config'
                                mock_report += f"  - Match Result: {match_result}\n"
                                if evaluation['type'] == 'ip':
                                    mock_report += "  - Rule Match Type: CIDR rule match\n"
                                elif evaluation['type'] == 'fqdn':
                                    mock_report += "  - Rule Match Type: FQDN rule match\n"
                                elif evaluation['type'] == 'srv':
                                    mock_report += "  - Rule Match Type: DNS SRV rule match\n"
                                else:
                                    mock_report += "  - Rule Match Type: Not applicable\n"
                                mock_report += f"  - Source Match Objects: {summary['matched_configs']}\n"

                                if evaluation['type'] == 'ip':
                                    mock_report += "  - Matched Include Rule(s):\n"
                                    if evaluation['cidr_include_matches']:
                                        for value in sorted(set(evaluation['cidr_include_matches'])):
                                            mock_report += f"    {value}\n"
                                    else:
                                        mock_report += "    None\n"

                                    mock_report += "  - Matched Exclude Rule(s):\n"
                                    if evaluation['cidr_exclude_matches']:
                                        for value in sorted(set(evaluation['cidr_exclude_matches'])):
                                            mock_report += f"    {value}\n"
                                    else:
                                        mock_report += "    None\n"

                                if evaluation['type'] in {'fqdn', 'srv'}:
                                    mock_report += "  - Matched Include Rule(s):\n"
                                    if evaluation['dns_include_matches']:
                                        for value in sorted(set(evaluation['dns_include_matches'])):
                                            mock_report += f"    {value} -> {evaluation['target']}\n"
                                    else:
                                        mock_report += "    None\n"

                                    mock_report += "  - Matched Exclude Rule(s):\n"
                                    if evaluation['dns_exclude_matches']:
                                        for value in sorted(set(evaluation['dns_exclude_matches'])):
                                            mock_report += f"    {value} -> {evaluation['target']}\n"
                                    else:
                                        mock_report += "    None\n"

                                if evaluation['type'] == 'invalid':
                                    mock_report += "  - Error: Input is not a valid IP, FQDN, or SRV value.\n"

                        for summary in flow_summaries:
                            if summary['parse_errors']:
                                mock_report += f"\n[{summary['flow']} Include/Exclude Parse Warnings]\n"
                                for warning in summary['parse_errors']:
                                    mock_report += f"  - {warning}\n"

                    if zta_access_mode == 'SPA' and spa_check_option == 'SRV Check':
                        if not srv_flow_filter_value:
                            search_term = str(srv_config_filter_value or '').strip()
                            srv_parse_errors = []
                            per_file_results = []

                            for json_file in json_candidates:
                                try:
                                    extracted = extract_spa_dns_include_entries(json_file)
                                    per_file_results.append({
                                        "path": os.path.relpath(json_file, temp_dir),
                                        "dns_include": extracted["dns_include"],
                                        "matched_spa_resource_configs": extracted["matched_spa_resource_configs"],
                                        "used_index_zero_fallback": extracted["used_index_zero_fallback"],
                                    })
                                except (json.JSONDecodeError, OSError) as exc:
                                    srv_parse_errors.append(f"{os.path.relpath(json_file, temp_dir)} -> {exc}")

                            overall_matches = []
                            lowered_target = search_term.lower()
                            for item in per_file_results:
                                if search_term:
                                    file_matches = [
                                        value
                                        for value in item["dns_include"]
                                        if lowered_target in value.lower() or srv_query_matches_rule(search_term, value)
                                    ]
                                else:
                                    file_matches = list(item["dns_include"])

                                if file_matches:
                                    overall_matches.append((item["path"], sorted(set(file_matches))))

                            if overall_matches:
                                unique_matches = sorted(set(
                                    value
                                    for _, matches in overall_matches
                                    for value in matches
                                ))
                                mock_report += "\n"
                                for value in unique_matches:
                                    mock_report += f"{value}\n"
                            else:
                                mock_report += "\nNo matching logs found.\n"

                            if srv_parse_errors:
                                mock_report += "\n[SPA SRV Check Parse Warnings]\n"
                                for warning in srv_parse_errors:
                                    mock_report += f"  - {warning}\n"
                        else:
                            mock_report += "\n[SPA SRV Flow Check]\n"
                            mock_report += f"  - SRV Filter: {srv_flow_filter_value}\n"
                            if srv_flow_time_start or srv_flow_time_end:
                                mock_report += (
                                    "  - Timeframe Filter (DART Time): "
                                    f"{format_bundle_filter_datetime(effective_srv_flow_start_dt, bundle_timezone, bundle_timezone_name)} -> "
                                    f"{format_bundle_filter_datetime(effective_srv_flow_end_dt, bundle_timezone, bundle_timezone_name)}\n"
                                )

                            srv_flow_attempts = find_spa_srv_flow_attempts(
                                temp_dir,
                                srv_flow_filter_value,
                                timeframe_start=effective_srv_flow_start_dt,
                                timeframe_end=effective_srv_flow_end_dt,
                            )

                            if srv_flow_attempts:
                                mock_report += f"\nTotal SRV Flow Attempts: {len(srv_flow_attempts)}\n"
                                for attempt_index, attempt in enumerate(srv_flow_attempts, start=1):
                                    timeframe_text = attempt['timeframe_start']
                                    if attempt['timeframe_end'] != attempt['timeframe_start']:
                                        timeframe_text = f"{attempt['timeframe_start']} -> {attempt['timeframe_end']}"
                                    srv_values_text = ", ".join(attempt.get('srv_values', [])) or srv_flow_filter_value
                                    mock_report += f"\nSRV Attempt {attempt_index}\n"
                                    mock_report += "-------------------\n"
                                    mock_report += f"Identifier: {attempt['identifier']}\n"
                                    mock_report += f"Events: {attempt['event_count']}\n"
                                    mock_report += f"Timeframe: {timeframe_text}\n"
                                    mock_report += f"SRV: {srv_values_text}\n"

                                    srv_flow_candidates_payload.append(
                                        {
                                            "attempt": attempt_index,
                                            "identifier": attempt['identifier'],
                                            "event_count": attempt['event_count'],
                                            "timeframe_start": attempt['timeframe_start'],
                                            "timeframe_end": attempt['timeframe_end'],
                                            "srv": srv_values_text,
                                        }
                                    )

                                if srv_selected_identifier:
                                    trace_lines = find_zta_log_lines_by_identifier(
                                        temp_dir,
                                        srv_selected_identifier,
                                        timeframe_start=effective_srv_flow_start_dt,
                                        timeframe_end=effective_srv_flow_end_dt,
                                    )
                                    mock_report += (
                                        f"\n[Selected SRV Flow Trace: identifier={srv_selected_identifier}]\n"
                                    )
                                    if trace_lines:
                                        for entry in trace_lines:
                                            relative_path = os.path.relpath(entry['path'], temp_dir)
                                            mock_report += (
                                                f"  - {relative_path}:L{entry['line_number']}\n"
                                                f"    {entry['line']}\n"
                                            )
                                        srv_selected_identifier_trace_payload = trace_lines
                                    else:
                                        mock_report += "  - No matching logs found.\n"
                            else:
                                mock_report += "\nNo matching logs found.\n"

                    if (
                        (zta_access_mode == 'SPA' and spa_check_option == 'Check TCP or UDP Flow')
                        or (zta_access_mode == 'SIA' and spa_check_option == 'Check SIA Flow')
                    ):
                        active_flow_mode = 'SPA' if zta_access_mode == 'SPA' else 'SIA'
                        # Flow Analysis evaluates the target against the entire cached
                        # config (both SPA and SIA steering configs), so destinations
                        # steered by either flow are detected regardless of the mode.
                        flow_steering_config_ids = ('spa_steering_config', 'tia_steering_config')
                        active_flow_label = (
                            'SPA TCP/UDP Redirected Flow Check'
                            if active_flow_mode == 'SPA'
                            else 'SIA TCP/UDP Redirected Flow Check'
                        )

                        flow_resource_results = []
                        flow_parse_errors = []
                        for json_file in json_candidates:
                            try:
                                for steering_config_id in flow_steering_config_ids:
                                    flow_resource_results.append(
                                        extract_include_exclude_from_resource_configs(
                                            json_file,
                                            steering_config_id,
                                        )
                                    )
                            except (json.JSONDecodeError, OSError) as exc:
                                flow_parse_errors.append(
                                    f"{os.path.relpath(json_file, temp_dir)} -> {exc}"
                                )

                        flow_cidr_include_rules = sorted(set(
                            value
                            for result in flow_resource_results
                            for value in result["cidr_include"]
                        ))
                        flow_cidr_exclude_rules = sorted(set(
                            value
                            for result in flow_resource_results
                            for value in result["cidr_exclude"]
                        ))
                        flow_fqdn_include_values = sorted(set(
                            value
                            for result in flow_resource_results
                            for value in result["fqdn_include"]
                        ))
                        flow_fqdn_exclude_values = sorted(set(
                            value
                            for result in flow_resource_results
                            for value in result["fqdn_exclude"]
                        ))
                        flow_dns_include_values = sorted(set(
                            value
                            for result in flow_resource_results
                            for value in result["dns_include"]
                        ))
                        flow_dns_exclude_values = sorted(set(
                            value
                            for result in flow_resource_results
                            for value in result["dns_exclude"]
                        ))

                        # Domain rules may live under fqdn and/or dns sections (SPA vs SIA
                        # store them differently). Cross-merge both so a valid target is
                        # not rejected just because it sits in the other section.
                        flow_fqdn_include_rules = sorted(set(flow_fqdn_include_values + flow_dns_include_values))
                        flow_fqdn_exclude_rules = sorted(set(flow_fqdn_exclude_values + flow_dns_exclude_values))
                        flow_dns_include_rules = sorted(set(flow_dns_include_values + flow_fqdn_include_values))
                        flow_dns_exclude_rules = sorted(set(flow_dns_exclude_values + flow_fqdn_exclude_values))

                        flow_target_cached_config_evaluation = evaluate_spa_target_against_include_exclude(
                            spa_target_value,
                            flow_cidr_include_rules,
                            flow_cidr_exclude_rules,
                            flow_fqdn_include_rules,
                            flow_fqdn_exclude_rules,
                            flow_dns_include_rules,
                            flow_dns_exclude_rules,
                        )

                        raw_flow_target_value = str(spa_target_value or '').strip().lower().rstrip('.')
                        bare_token_target_match = False
                        if raw_flow_target_value and '.' not in raw_flow_target_value:
                            candidate_rules = flow_fqdn_include_rules + flow_fqdn_exclude_rules + flow_dns_include_rules + flow_dns_exclude_rules
                            bare_token_target_match = any(
                                raw_flow_target_value in str(rule or '').strip().lower().rstrip('.')
                                for rule in candidate_rules
                            )

                        target_exists_in_flow_cached_config = (
                            flow_target_cached_config_evaluation.get("classification")
                            in {"included", "excluded", "both include and exclude matched"}
                        ) or bare_token_target_match

                        mock_report += "\n"
                        mock_report += f"  - Search Target: {spa_target_value}\n"
                        if flow_filter_destination_port:
                            mock_report += f"  - Destination Port Filter: {flow_filter_destination_port}\n"
                        if flow_filter_time_start or flow_filter_time_end:
                            mock_report += (
                                "  - Timeframe Filter (DART Time): "
                                f"{format_bundle_filter_datetime(effective_flow_filter_start_dt, bundle_timezone, bundle_timezone_name)} -> "
                                f"{format_bundle_filter_datetime(effective_flow_filter_end_dt, bundle_timezone, bundle_timezone_name)}\n"
                            )

                        if not target_exists_in_flow_cached_config:
                            target_type_text = flow_target_cached_config_evaluation.get("type") or "unknown"
                            mock_report += f"  - Target Type: {target_type_text}\n"
                            mock_report += (
                                "  - Target is not present in the cached config "
                                "(checked SPA and SIA steering configs).\n"
                            )
                            mock_report += "  - No matching logs found.\n"
                        else:
                            flow_results = find_spa_redirected_flows(
                                temp_dir,
                                spa_target_value,
                                destination_port_filter=flow_filter_destination_port,
                                timeframe_start=effective_flow_filter_start_dt,
                                timeframe_end=effective_flow_filter_end_dt,
                            )

                            if flow_results["matches"]:
                                if flow_results["timeframe_start"] and flow_results["timeframe_end"]:
                                    mock_report += (
                                        f"  - Timeframe: {flow_results['timeframe_start']} -> "
                                        f"{flow_results['timeframe_end']}\n"
                                    )

                                for index, match in enumerate(flow_results["matches"], start=1):
                                    mock_report += f"\n  - Match #{index}\n"
                                    mock_report += f"    Time: {match['timestamp']}\n"
                                    mock_report += (
                                        f"    TCP/UDP Destination:Port: "
                                        f"{match['protocol']} {match['destination']}:{match['destination_port']}\n"
                                    )
                                    if match['real_destination_ip']:
                                        mock_report += f"    Real Destination IP: {match['real_destination_ip']}\n"
                                    mock_report += f"    Source Port: {match['source_port']}\n"
                                    mock_report += (
                                        f"    Process: {match['process_name']} (PID {match['process_pid']})\n"
                                    )
                                    mock_report += f"    User: {match['process_user']}\n"
                                    mock_report += (
                                        f"    Parent Process: {match['parent_process_name']} "
                                        f"(PID {match['parent_process_pid']})\n"
                                    )
                                    mock_report += f"    Parent User: {match['parent_process_user']}\n"
                                    mock_report += f"    Match Rule Type: {match['match_rule_type']}\n"

                                    destination_evaluation = evaluate_spa_target_against_include_exclude(
                                        match['destination'],
                                        flow_cidr_include_rules,
                                        flow_cidr_exclude_rules,
                                        flow_fqdn_include_rules,
                                        flow_fqdn_exclude_rules,
                                        flow_dns_include_rules,
                                        flow_dns_exclude_rules,
                                    )
                                    destination_match_result = destination_evaluation['classification']
                                    if destination_match_result == 'no include/exclude match':
                                        destination_match_result = 'resource does not exist in cached config'
                                    mock_report += (
                                        f"    Destination Cached Config Match: {destination_match_result}\n"
                                    )

                                if flow_selected_src_port:
                                    matched_source_ports = {
                                        str(match.get('source_port', '')).strip()
                                        for match in flow_results["matches"]
                                        if str(match.get('source_port', '')).strip()
                                    }
                                    selected_source_port = str(flow_selected_src_port).strip()

                                    mock_report += f"\n[Selected Flow Trace: srcPort={flow_selected_src_port}]\n"
                                    if selected_source_port and selected_source_port not in matched_source_ports:
                                        mock_report += "  - No matching logs found.\n"
                                        mock_report += (
                                            "  - Selected Source Port is not in current SPA flow matches. "
                                            "Choose a Source Port from the Match list above.\n"
                                        )
                                    else:
                                        trace_lines = find_zta_log_lines_by_source_port(
                                            temp_dir,
                                            flow_selected_src_port,
                                        )
                                        if trace_lines:
                                            mock_report += f"  - Matched Lines: {len(trace_lines)}\n"
                                            for entry in trace_lines:
                                                relative_path = os.path.relpath(entry['path'], temp_dir)
                                                mock_report += (
                                                    f"  - {relative_path}:L{entry['line_number']}\n"
                                                    f"    {entry['line']}\n"
                                                )
                                        else:
                                            mock_report += "  - No matching logs found.\n"
                                else:
                                    mock_report += (
                                        "\n  - Next Step: choose one flow Source Port from the matches above, "
                                        "enter it in the Source Port field, and run again to trace all lines.\n"
                                    )
                            else:
                                mock_report += "  - No matching logs found.\n"

                        if flow_parse_errors:
                            mock_report += f"\n[{active_flow_mode} Flow Parse Warnings]\n"
                            for warning in flow_parse_errors:
                                mock_report += f"  - {warning}\n"

                    if zta_access_mode in {'SPA', 'SIA'} and spa_check_option == 'Check Trusted Network Detection':
                        tnd_parse_errors = []
                        flow_summaries = []

                        for flow_mode in ('SPA', 'SIA'):
                            tnd_config_rows = []
                            for json_file in json_candidates:
                                try:
                                    relative_path = os.path.relpath(json_file, temp_dir)
                                    extracted_configs = extract_spa_trusted_network_detection(
                                        json_file,
                                        flow_filter=flow_mode,
                                    )
                                    for config_row in extracted_configs:
                                        config_row_with_source = dict(config_row)
                                        config_row_with_source["source_path"] = relative_path
                                        tnd_config_rows.append(config_row_with_source)
                                except (json.JSONDecodeError, OSError) as exc:
                                    tnd_parse_errors.append(
                                        f"{flow_mode}: {os.path.relpath(json_file, temp_dir)} -> {exc}"
                                    )

                            flow_summary = {
                                "flow": flow_mode,
                                "proxy_config_id": "default_spa_config" if flow_mode == 'SPA' else "default_tia_config",
                                "proxy_config_label": "Secure Private Access" if flow_mode == 'SPA' else "Secure Internet Access",
                                "proxy_config_found": False,
                                "match_network_fingerprint_configured": False,
                                "conditional_actions": set(),
                                "matched_fingerprint_refs": set(),
                                "dns_servers": set(),
                                "domains": set(),
                                "trusted_servers": set(),
                            }

                            for row in tnd_config_rows:
                                if row.get("proxy_config_found"):
                                    flow_summary["proxy_config_found"] = True
                                if row.get("match_network_fingerprint_configured"):
                                    flow_summary["match_network_fingerprint_configured"] = True
                                flow_summary["conditional_actions"].update(row.get("conditional_actions", []))
                                flow_summary["matched_fingerprint_refs"].update(row.get("matched_fingerprint_refs", []))
                                flow_summary["dns_servers"].update(row.get("dns_servers", []))
                                flow_summary["domains"].update(row.get("domains", []))
                                flow_summary["trusted_servers"].update(row.get("trusted_servers", []))

                            flow_summaries.append(flow_summary)

                        # Runtime detection from the csc_zta_agent ZTA logs (Cisco "From DART
                        # Bundle - ZTA Logs" verification flow). Determines the actual live TND
                        # state per proxy config (Paused by TND / no rules / configured but not
                        # on a trusted network) in addition to the config-derived detection.
                        tnd_runtime = analyze_trusted_network_detection_runtime(temp_dir)
                        tnd_runtime_flows = tnd_runtime.get("flows", {})
                        for flow_summary in flow_summaries:
                            runtime_info = tnd_runtime_flows.get(flow_summary["flow"], {})
                            flow_summary["runtime_found"] = bool(runtime_info.get("runtime_found"))
                            flow_summary["runtime_status"] = runtime_info.get("runtime_status", "Unknown")
                            flow_summary["paused_by_tnd"] = bool(runtime_info.get("paused_by_tnd"))
                            flow_summary["tnd_rules_present"] = runtime_info.get("tnd_rules_present")
                            flow_summary["pause_start"] = runtime_info.get("pause_start", "")
                            flow_summary["pause_end"] = runtime_info.get("pause_end", "")
                            flow_summary["runtime_matched_fingerprints"] = set(
                                runtime_info.get("matched_fingerprints", set())
                            )
                            flow_summary["pause_conditions"] = set(runtime_info.get("pause_conditions", set()))
                            flow_summary["closed_flows"] = list(runtime_info.get("closed_flows", []))

                        mock_report += "\n[Trusted Network Detection]\n"
                        for flow_summary in flow_summaries:
                            # A trusted network is considered detected only when conditional actions exist.
                            # Fingerprints/criteria alone indicate configuration exists but not active detection rules.
                            fingerprints_detected = bool(flow_summary["conditional_actions"])

                            mock_report += f"\n[{flow_summary['flow']} Trusted Network Detection]\n"
                            mock_report += (
                                f"  - Detection Status: {'Detected' if fingerprints_detected else 'Not Detected'}\n"
                            )
                            mock_report += (
                                f"  - Runtime Status (ZTA logs): {flow_summary['runtime_status']}\n"
                            )
                            if flow_summary["pause_conditions"]:
                                mock_report += "  - Pause Conditions:\n"
                                for pause_condition in sorted(flow_summary["pause_conditions"]):
                                    mock_report += f"    - {pause_condition}\n"
                            if flow_summary["closed_flows"]:
                                mock_report += "  - App Flows Closed by TND:\n"
                                for closed_flow in flow_summary["closed_flows"]:
                                    destination = closed_flow.get("destination") or "unknown"
                                    rule_type = closed_flow.get("match_rule_type") or "unknown"
                                    mock_report += f"    - {destination} (matchRuleType={rule_type})\n"

                            if flow_summary["conditional_actions"]:
                                mock_report += "  - Conditional Actions:\n"
                                for conditional_action in sorted(flow_summary["conditional_actions"]):
                                    mock_report += f"    - {conditional_action}\n"
                            else:
                                mock_report += "  - Conditional Actions: Not set\n"

                            if flow_summary["matched_fingerprint_refs"]:
                                mock_report += (
                                    "  - Network Fingerprints Configured: "
                                    f"{', '.join(sorted(flow_summary['matched_fingerprint_refs']))}\n"
                                )
                            else:
                                mock_report += "  - Network Fingerprints Configured: None\n"

                            mock_report += "  - Matching Criteria:\n"
                            if flow_summary["domains"]:
                                mock_report += "    Domains:\n"
                                for domain in sorted(flow_summary["domains"]):
                                    mock_report += f"      - {domain}\n"
                            else:
                                mock_report += "    Domains: None\n"

                            if flow_summary["dns_servers"]:
                                mock_report += "    DNS Servers:\n"
                                for dns_server in sorted(flow_summary["dns_servers"]):
                                    mock_report += f"      - {dns_server}\n"
                            else:
                                mock_report += "    DNS Servers: None\n"

                            if flow_summary["trusted_servers"]:
                                mock_report += "    Trusted Servers:\n"
                                for trusted_server in sorted(flow_summary["trusted_servers"]):
                                    mock_report += f"      - {trusted_server}\n"
                            else:
                                mock_report += "    Trusted Servers: None\n"

                        if tnd_parse_errors:
                            mock_report += "\n[Trusted Network Detection Parse Warnings]\n"
                            for warning in tnd_parse_errors:
                                mock_report += f"  - {warning}\n"

                        tnd_network_fingerprint_events = tnd_runtime.get("network_fingerprint_events", [])
                        tnd_network_snapshots = tnd_runtime.get("network_snapshots", [])

                        if tnd_network_fingerprint_events:
                            mock_report += "\n[Network Fingerprints Matched]\n"
                            for event in tnd_network_fingerprint_events:
                                mock_report += (
                                    f"  - {event.get('fingerprint', 'unknown')} "
                                    f"(interfaces: {event.get('interfaces', 'unknown')})\n"
                                )

                        if tnd_network_snapshots:
                            mock_report += "\n[Network Snapshot]\n"
                            for snapshot in tnd_network_snapshots:
                                mock_report += (
                                    f"  - {snapshot.get('interface', 'unknown')}: "
                                    f"dns_servers={snapshot.get('dns_servers', '')} "
                                    f"dns_domain={snapshot.get('dns_domain', '')} "
                                    f"dns_suffixes={snapshot.get('dns_suffixes', '')}\n"
                                )

                        tnd_summary_payload = {
                            "flows": [
                                {
                                    "flow": flow_summary["flow"],
                                    "proxy_config_label": flow_summary["proxy_config_label"],
                                    "proxy_config_id": flow_summary["proxy_config_id"],
                                    "proxy_config_found": bool(flow_summary["proxy_config_found"]),
                                    "detected": bool(flow_summary["conditional_actions"]),
                                    "match_network_fingerprint_configured": bool(
                                        flow_summary["match_network_fingerprint_configured"]
                                    ),
                                    "conditional_actions": sorted(flow_summary["conditional_actions"]),
                                    "network_fingerprints": sorted(flow_summary["matched_fingerprint_refs"]),
                                    "domains": sorted(flow_summary["domains"]),
                                    "dns_servers": sorted(flow_summary["dns_servers"]),
                                    "trusted_servers": sorted(flow_summary["trusted_servers"]),
                                    "runtime_found": bool(flow_summary.get("runtime_found")),
                                    "runtime_status": flow_summary.get("runtime_status", "Unknown"),
                                    "paused_by_tnd": bool(flow_summary.get("paused_by_tnd")),
                                    "pause_start": flow_summary.get("pause_start", ""),
                                    "pause_end": flow_summary.get("pause_end", ""),
                                    "pause_conditions": sorted(flow_summary.get("pause_conditions", set())),
                                    "runtime_matched_fingerprints": sorted(
                                        flow_summary.get("runtime_matched_fingerprints", set())
                                    ),
                                    "closed_flows": list(flow_summary.get("closed_flows", [])),
                                }
                                for flow_summary in flow_summaries
                            ],
                            "network_fingerprint_events": tnd_network_fingerprint_events,
                            "network_snapshots": tnd_network_snapshots,
                            "parse_warnings": list(tnd_parse_errors),
                        }

                    if zta_access_mode in {'SPA', 'SIA'} and spa_check_option == 'Check User Pause Config':
                        mock_report += "\n[User Pause Config]\n"
                        pause_parse_errors = []

                        # Configured user_pause_configs entries (id / label / resume_timeout)
                        # from the cached ZTA config JSON, e.g. "Pause SPA" resume_timeout 1800.
                        pause_config_entries = []
                        for json_file in json_candidates:
                            try:
                                pause_config_entries.extend(
                                    extract_user_pause_config_entries(json_file)
                                )
                            except (json.JSONDecodeError, OSError) as exc:
                                pause_parse_errors.append(
                                    f"config: {os.path.relpath(json_file, temp_dir)} -> {exc}"
                                )

                        def match_pause_flow(entry):
                            combined = f"{entry.get('id', '')} {entry.get('label', '')}".lower()
                            if "spa" in combined:
                                return "SPA"
                            if "tia" in combined or "sia" in combined:
                                return "SIA"
                            return None

                        pause_config_by_flow = {}
                        for entry in pause_config_entries:
                            flow_key = match_pause_flow(entry)
                            if flow_key and flow_key not in pause_config_by_flow:
                                pause_config_by_flow[flow_key] = entry

                        # Runtime user-pause state from the csc_zta_agent / csc_zta_api ZTA logs
                        # (InitiatePause -> handlePauseRequest -> PauseProxyConfig -> Pause request
                        # completed -> User pause will disconnect -> InactiveUserPaused).
                        user_pause_runtime = analyze_user_pause_runtime(temp_dir)
                        user_pause_runtime_flows = user_pause_runtime.get("flows", {})

                        flow_definitions = {
                            "SPA": {"proxy_config_id": "default_spa_config", "proxy_config_label": "Secure Private Access"},
                            "SIA": {"proxy_config_id": "default_tia_config", "proxy_config_label": "Secure Internet Access"},
                        }

                        user_pause_flow_payloads = []
                        for flow_mode in ('SPA', 'SIA'):
                            definition = flow_definitions[flow_mode]
                            config_entry = pause_config_by_flow.get(flow_mode)
                            runtime_info = user_pause_runtime_flows.get(flow_mode, {})
                            config_found = config_entry is not None
                            resume_timeout = config_entry.get("resume_timeout") if config_entry else None
                            paused_by_user = bool(runtime_info.get("paused_by_user"))
                            pause_requested = bool(runtime_info.get("pause_requested"))

                            mock_report += f"\n[{flow_mode} User Pause Config]\n"
                            mock_report += (
                                f"  - {flow_mode} User Pause Config: {'Detected' if config_found else 'Not Detected'}\n"
                            )
                            if config_found:
                                mock_report += f"    - Pause Config ID: {config_entry.get('id', '')}\n"
                                mock_report += f"    - Pause Label: {config_entry.get('label', '')}\n"
                                mock_report += (
                                    f"    - Resume Timeout: "
                                    f"{resume_timeout if resume_timeout is not None else 'Unknown'} seconds\n"
                                )
                            mock_report += (
                                f"  - Runtime Status (ZTA logs): {runtime_info.get('runtime_status', 'Unknown')}\n"
                            )
                            if runtime_info.get("max_duration_seconds") is not None:
                                mock_report += (
                                    f"    - Pause Max Duration (log): {runtime_info.get('max_duration_seconds')} seconds\n"
                                )
                            if runtime_info.get("pause_result"):
                                mock_report += f"    - Pause Result: {runtime_info.get('pause_result')}\n"
                            if runtime_info.get("enrollment_id"):
                                mock_report += f"    - Enrollment ID: {runtime_info.get('enrollment_id')}\n"
                            if paused_by_user:
                                pause_start = runtime_info.get("pause_start", "")
                                pause_end = runtime_info.get("pause_end", "")
                                if pause_start and pause_end and pause_start != pause_end:
                                    mock_report += f"    - Pause Time Frame: {pause_start} -> {pause_end}\n"
                                elif pause_start or pause_end:
                                    mock_report += f"    - Pause Time: {pause_start or pause_end}\n"

                            user_pause_flow_payloads.append(
                                {
                                    "flow": flow_mode,
                                    "proxy_config_id": definition["proxy_config_id"],
                                    "proxy_config_label": definition["proxy_config_label"],
                                    "config_found": config_found,
                                    "pause_config_id": config_entry.get("id", "") if config_entry else "",
                                    "pause_config_label": config_entry.get("label", "") if config_entry else "",
                                    "resume_timeout": resume_timeout,
                                    "runtime_found": bool(runtime_info.get("runtime_found")),
                                    "runtime_status": runtime_info.get("runtime_status", "Unknown"),
                                    "paused_by_user": paused_by_user,
                                    "pause_requested": pause_requested,
                                    "pause_applied": bool(runtime_info.get("pause_applied")),
                                    "will_disconnect": bool(runtime_info.get("will_disconnect")),
                                    "max_duration_seconds": runtime_info.get("max_duration_seconds"),
                                    "pause_result": runtime_info.get("pause_result", ""),
                                    "enrollment_id": runtime_info.get("enrollment_id", ""),
                                    "pause_start": runtime_info.get("pause_start", ""),
                                    "pause_end": runtime_info.get("pause_end", ""),
                                }
                            )

                        if pause_parse_errors:
                            mock_report += "\n[User Pause Config Parse Warnings]\n"
                            for warning in pause_parse_errors:
                                mock_report += f"  - {warning}\n"

                        user_pause_summary_payload = {
                            "pause_initiated": bool(user_pause_runtime.get("pause_initiated")),
                            "flows": user_pause_flow_payloads,
                            "parse_warnings": list(pause_parse_errors),
                        }

                    if show_full_cached_config:
                        if cached_config_search_term:
                            cached_config_matches = search_cached_config_files(
                                json_candidates,
                                temp_dir,
                                cached_config_search_term,
                            )
                            cached_config_match_flows = summarize_cached_config_match_flows(cached_config_matches)
                            if not cached_config_search_only_output:
                                mock_report += f"\n[Cached Config Search: {cached_config_search_term}]\n"
                                if (
                                    zta_access_mode in {'SPA', 'SIA'}
                                    and spa_check_option == 'Check SIA Flow'
                                ):
                                    opposite_flow = 'SIA' if zta_access_mode == 'SPA' else 'SPA'
                                    if opposite_flow in cached_config_match_flows:
                                        mock_report += (
                                            f"  - Note: cached config search hits were found under {opposite_flow}, "
                                            f"while the include/exclude result above is evaluating {zta_access_mode} only.\n"
                                        )
                            if cached_config_matches:
                                for match in cached_config_matches:
                                    if not cached_config_search_only_output:
                                        mock_report += f"  - File: {match['path']}\n"
                                    if match['error']:
                                        if cached_config_search_only_output:
                                            mock_report += f"Error: {match['error']}\n"
                                        else:
                                            mock_report += f"    Error: {match['error']}\n"
                                        continue
                                    for matched_line in match['matched_lines']:
                                        result_label = matched_line['flow']
                                        if matched_line.get('direction') and matched_line['direction'] != 'Unknown':
                                            result_label = f"{result_label} | {matched_line['direction']}"
                                        if cached_config_search_only_output:
                                            mock_report += (
                                                f"[{result_label}] "
                                                f"L{matched_line['line_number']}: "
                                                f"{matched_line['line_text']}\n"
                                            )
                                        else:
                                            mock_report += (
                                                f"    [{result_label}] "
                                                f"L{matched_line['line_number']}: "
                                                f"{matched_line['line_text']}\n"
                                            )
                            else:
                                if cached_config_search_only_output:
                                    mock_report += "No matching logs found.\n"
                                else:
                                    mock_report += "  - No matching logs found.\n"
                        else:
                            cached_config_dump = render_cached_config_files(json_candidates, temp_dir)
                            if cached_config_dump:
                                mock_report += "\n[Complete Cached Config]\n"
                                mock_report += cached_config_dump
                                mock_report += "\n"

            if selected_module == 'Duo Desktop':
                duo_log_results = collect_duo_desktop_failed_error_lines(temp_dir)
                duo_user_folders = duo_log_results.get("user_folders", [])
                duo_matches = duo_log_results.get("matches", [])
                duo_user_log_files = find_duo_desktop_user_log_files(temp_dir)
                service_log_files = find_duo_desktop_service_log_files(temp_dir)
                service_logs_by_section = categorize_duo_service_log_files(service_log_files)
                posture_filter_active = bool(duo_posture_filter)

                if posture_filter_active:
                    mock_report += "\n"
                    posture_log_paths = [
                        path
                        for path in duo_user_log_files
                        if os.path.basename(path).lower().startswith("duodesktop")
                        and os.path.basename(path).lower().endswith(".log")
                    ]
                    posture_matches = collect_matching_lines_from_log_files(
                        posture_log_paths,
                        duo_posture_filter,
                    )

                    if not posture_matches:
                        mock_report += "No matching logs found.\n"
                    else:
                        posture_window = extract_duo_match_time_window(
                            posture_matches,
                            bundle_timezone,
                            bundle_timezone_name,
                        )
                        posture_start = posture_window.get("start")
                        posture_end = posture_window.get("end")
                        if posture_start and posture_end:
                            if posture_start == posture_end:
                                mock_report += f"Overall Timeframe: {posture_start}\n"
                            else:
                                formatted_timeframe = format_timeframe_single_timezone(posture_start, posture_end)
                                mock_report += f"Overall Timeframe: {formatted_timeframe}\n"
                        else:
                            mock_report += "Overall Timeframe: Not found\n"

                        posture_summaries = summarize_duo_filtered_lines_with_timeframes(
                            posture_matches,
                            bundle_timezone,
                            bundle_timezone_name,
                            max_items=80,
                        )
                        duo_posture_flow_summary_payload = {
                            "filter": duo_posture_filter,
                            "timeframe_start": split_timestamp_and_timezone(posture_start).get("timestamp", "Not found") if posture_start else "Not found",
                            "timeframe_end": split_timestamp_and_timezone(posture_end).get("timestamp", "Not found") if posture_end else "Not found",
                            "timezone": split_timestamp_and_timezone(posture_end).get("timezone", "") if posture_end else "",
                            "rows": [
                                {
                                    "pattern": item.get("pattern", ""),
                                    "hits": item.get("hits", 0),
                                    "first_seen": item.get("first_seen", "Not found"),
                                    "last_seen": item.get("last_seen", "Not found"),
                                    "download_text": item.get("download_text", ""),
                                    "download_filename": item.get("download_filename", "duo_posture_pattern.log"),
                                }
                                for item in posture_summaries
                            ],
                        }
                else:
                    mock_report += "\n[Duo Desktop Logs]\n"
                    if not duo_user_folders:
                        mock_report += "Duo Desktop Diagnostics - Not Enabled.\n"
                    else:
                        if duo_matches:
                            duo_match_window = extract_duo_match_time_window(
                                duo_matches,
                                bundle_timezone,
                                bundle_timezone_name,
                            )
                            duo_start = duo_match_window.get("start")
                            duo_end = duo_match_window.get("end")
                            if duo_start and duo_end:
                                if duo_start == duo_end:
                                    mock_report += f"Timeframe: {duo_start}\n"
                                else:
                                    formatted_timeframe = format_timeframe_single_timezone(duo_start, duo_end)
                                    mock_report += f"Timeframe: {formatted_timeframe}\n"
                            else:
                                mock_report += "Timeframe: Not found\n"

                            condensed_duo_lines = summarize_duo_match_lines(duo_matches)
                            if condensed_duo_lines:
                                for item in condensed_duo_lines:
                                    mock_report += f"  - {item['sample']}\n"
                        else:
                            mock_report += "  - No matching logs found.\n"

                    mock_report += "\n[Health Report]\n"
                    if duo_user_log_files:
                        health_status = analyze_duo_health_report_status(
                            duo_user_log_files,
                            bundle_timezone,
                            bundle_timezone_name,
                        )
                        health_window = health_status.get("timeframe", {})
                        health_start = health_window.get("start")
                        health_end = health_window.get("end")
                        if health_start and health_end:
                            if health_start == health_end:
                                mock_report += f"Timeframe: {health_start}\n"
                            else:
                                formatted_timeframe = format_timeframe_single_timezone(health_start, health_end)
                                mock_report += f"Timeframe: {formatted_timeframe}\n"

                        if health_status.get("sent_count", 0) == 0:
                            mock_report += "Status: No health report send/response entries found.\n"
                        else:
                            if health_status.get("missing_count", 0) > 0:
                                mock_report += (
                                    "Status: Missing health report response(s). "
                                    f"Sent={health_status.get('sent_count', 0)}, "
                                    f"200_OK={health_status.get('ok_count', 0)}, "
                                    f"Missing={health_status.get('missing_count', 0)}\n"
                                )
                                health_errors = summarize_duo_match_lines(
                                    health_status.get("error_matches", []),
                                    max_items=25,
                                )
                                if health_errors:
                                    mock_report += "Related Errors:\n"
                                    for item in health_errors:
                                        mock_report += f"  - {item['sample']}\n"

                        health_transactions = health_status.get("transaction_lines", [])
                        if health_transactions:
                            mock_report += "Transactions:\n"
                            for line in health_transactions[:40]:
                                mock_report += f"  - {line}\n"
                    else:
                        mock_report += "Status: No Duo Desktop user log files found.\n"

                    for section_name in (
                        "Crypto Service logs",
                        "TrustedPeerMessageBroker Logs",
                        "Duo Desktop Updater logs",
                    ):
                        section_files = service_logs_by_section.get(section_name, [])
                        mock_report += f"\n[{section_name}]\n"
                        if not section_files:
                            mock_report += "No matching service logs found.\n"
                            continue

                        section_window = extract_log_time_window(
                            section_files,
                            bundle_timezone,
                            bundle_timezone_name,
                        )
                        section_start = section_window.get("start")
                        section_end = section_window.get("end")
                        if section_start and section_end:
                            if section_start == section_end:
                                mock_report += f"Timeframe: {section_start}\n"
                            else:
                                formatted_timeframe = format_timeframe_single_timezone(section_start, section_end)
                                mock_report += f"Timeframe: {formatted_timeframe}\n"
                        else:
                            mock_report += "Timeframe: Not found\n"

                        section_error_matches = collect_failed_error_lines_from_log_files(section_files)
                        if not section_error_matches:
                            mock_report += "No matching logs found.\n"
                            continue

                        condensed_section_errors = summarize_duo_match_lines(
                            section_error_matches,
                            max_items=40,
                        )
                        for item in condensed_section_errors:
                            mock_report += f"  - {item['sample']}\n"
            
            if (
                selected_module == 'ZTA'
                and
                not concise_include_exclude_output
                and not concise_zta_check_output
                and not show_full_cached_config
            ):
                # Show a sample of extracted files to prove it works
                mock_report += "\n[Extracted Archive Manifest - Sample]\n"
                for f in extracted_files[:20]:
                    mock_report += f"  ├── {f}\n"
                if len(extracted_files) > 20:
                    mock_report += f"  └── ... and {len(extracted_files) - 20} more files.\n"

                mock_report += "\n[!] Status: Ready. (Insert explicit log parsing logic here)"
            
            response_data = {
                "message": "Analysis complete",
                "module": selected_module,
                "details": mock_report
            }

            if (
                selected_module == 'ZTA'
                and zta_access_mode == 'SPA'
                and spa_check_option == 'SRV Check'
                and srv_flow_filter_value
            ):
                response_data["srv_flow_candidates"] = srv_flow_candidates_payload
                response_data["srv_selected_identifier"] = srv_selected_identifier
                response_data["srv_selected_identifier_trace"] = [
                    {
                        "path": os.path.relpath(entry['path'], temp_dir),
                        "line_number": entry['line_number'],
                        "line": entry['line'],
                    }
                    for entry in srv_selected_identifier_trace_payload
                ]

            if (
                selected_module == 'ZTA'
                and zta_access_mode == 'SPA'
                and spa_check_option == 'Check Server Connectivity Errors'
            ):
                response_data["server_connectivity_summary"] = connectivity_context.get("table_summary", {
                    "timeframe_start": "Unknown",
                    "timeframe_end": "Unknown",
                    "categories": [],
                })

            if (
                selected_module == 'ZTA'
                and zta_access_mode == 'SPA'
                and spa_check_option == 'Check Configuration Sync'
            ):
                response_data["config_sync_summary"] = config_sync_summary_payload

            if (
                selected_module == 'ZTA'
                and zta_access_mode == 'SPA'
                and spa_check_option == 'Check Event Viewer Logs'
                and event_viewer_filtered_download_text
            ):
                response_data["event_viewer_filtered_download_text"] = event_viewer_filtered_download_text
                response_data["event_viewer_filtered_download_filename"] = event_viewer_filtered_download_filename

            if (
                selected_module == 'ZTA'
                and zta_access_mode == 'SPA'
                and spa_check_option == 'Check Event Viewer Logs'
                and event_viewer_summary_payload
            ):
                response_data["event_viewer_summary"] = event_viewer_summary_payload

            if (
                selected_module == 'ZTA'
                and zta_access_mode in {'SPA', 'SIA'}
                and spa_check_option == 'Check Trusted Network Detection'
                and tnd_summary_payload
            ):
                response_data["tnd_summary"] = tnd_summary_payload

            if (
                selected_module == 'ZTA'
                and zta_access_mode in {'SPA', 'SIA'}
                and spa_check_option == 'Check User Pause Config'
                and user_pause_summary_payload
            ):
                response_data["user_pause_summary"] = user_pause_summary_payload

            if selected_module == 'Duo Desktop' and duo_posture_flow_summary_payload:
                response_data["duo_posture_flow_summary"] = duo_posture_flow_summary_payload

            if enrollment_flow_payload and enrollment_flow_payload.get("attempts"):
                response_data["enrollment_flow"] = enrollment_flow_payload
            
        except zipfile.BadZipFile:
            return jsonify({"error": "The uploaded payload is not a valid ZIP archive."}), 400
        finally:
            # Clean up the temp directory after analysis
            shutil.rmtree(temp_dir, ignore_errors=True)
            
        return jsonify(response_data)
        
    return jsonify({"error": "Invalid file type. Please upload a .zip file."}), 400


def parse_bool_env(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def get_feedback_mail_config():
    smtp_host = os.environ.get("DARTHAWK_FEEDBACK_SMTP_HOST", "").strip()
    smtp_port_raw = os.environ.get("DARTHAWK_FEEDBACK_SMTP_PORT", "587").strip()
    smtp_username = os.environ.get("DARTHAWK_FEEDBACK_SMTP_USERNAME", "").strip()
    smtp_password = os.environ.get("DARTHAWK_FEEDBACK_SMTP_PASSWORD", "")
    smtp_use_tls = parse_bool_env("DARTHAWK_FEEDBACK_SMTP_USE_TLS", default=True)
    sender = os.environ.get("DARTHAWK_FEEDBACK_FROM", "").strip() or smtp_username
    recipients_raw = os.environ.get("DARTHAWK_FEEDBACK_TO", "amarora2@cisco.com").strip()
    recipients = [item.strip() for item in recipients_raw.split(",") if item.strip()]

    try:
        smtp_port = int(smtp_port_raw)
    except ValueError:
        smtp_port = 587

    return {
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_username": smtp_username,
        "smtp_password": smtp_password,
        "smtp_use_tls": smtp_use_tls,
        "sender": sender,
        "recipients": recipients,
    }


def send_feedback_email(mail_config, subject, body, attachments):
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = mail_config["sender"]
    message["To"] = ", ".join(mail_config["recipients"])
    message.set_content(body)

    for attachment in attachments:
        filename = attachment["filename"]
        payload = attachment["content"]
        mime_type = attachment.get("mime_type") or "application/octet-stream"
        maintype, subtype = mime_type.split("/", 1) if "/" in mime_type else ("application", "octet-stream")
        message.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)

    smtp_host = mail_config["smtp_host"]
    smtp_port = mail_config["smtp_port"]
    smtp_username = mail_config["smtp_username"]
    smtp_password = mail_config["smtp_password"]
    smtp_use_tls = mail_config["smtp_use_tls"]

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as smtp_server:
        smtp_server.ehlo()
        if smtp_use_tls:
            smtp_server.starttls()
            smtp_server.ehlo()
        if smtp_username:
            smtp_server.login(smtp_username, smtp_password)
        smtp_server.send_message(message)


@app.route('/feedback', methods=['POST'])
def submit_feedback():
    feedback_os = request.form.get('feedback_os', '').strip()
    feedback_component = request.form.get('feedback_component', '').strip()
    feedback_issue = request.form.get('feedback_issue', '').strip()
    feedback_sr_number = request.form.get('feedback_sr_number', '').strip()
    feedback_dart_file_name = request.form.get('feedback_dart_file_name', '').strip()

    allowed_os = {'Windows', 'macOS', 'Linux'}
    allowed_components = {'ZTA'}

    if feedback_os not in allowed_os:
        return jsonify({"error": "Please select a valid OS."}), 400
    if feedback_component not in allowed_components:
        return jsonify({"error": "Please select a valid component."}), 400
    if not feedback_issue:
        return jsonify({"error": "Please describe the issue."}), 400

    mail_config = get_feedback_mail_config()
    if (
        not mail_config["smtp_host"]
        or not mail_config["sender"]
        or not mail_config["recipients"]
    ):
        return jsonify({
            "message": (
                "SMTP feedback email is not configured on this server. "
                "Using local email-app fallback."
            ),
            "fallback_mailto": True,
            "mailto_to": ",".join(mail_config["recipients"]),
        }), 200

    max_total_mb_raw = os.environ.get("DARTHAWK_FEEDBACK_MAX_TOTAL_MB", "25").strip()
    try:
        max_total_bytes = max(1, int(max_total_mb_raw)) * 1024 * 1024
    except ValueError:
        max_total_bytes = 25 * 1024 * 1024

    attachments = []
    total_size = 0

    screenshot_files = request.files.getlist('feedback_screenshots')
    for screenshot in screenshot_files:
        if not screenshot or not screenshot.filename:
            continue
        screenshot_name = os.path.basename(screenshot.filename)
        screenshot_bytes = screenshot.read()
        total_size += len(screenshot_bytes)
        guessed_mime = mimetypes.guess_type(screenshot_name)[0] or 'application/octet-stream'
        attachments.append({
            "filename": screenshot_name,
            "content": screenshot_bytes,
            "mime_type": guessed_mime,
        })

    if total_size > max_total_bytes:
        return jsonify({
            "error": (
                f"Total attachment size exceeds {max_total_bytes // (1024 * 1024)} MB. "
                "Please reduce file sizes and try again."
            )
        }), 400

    submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    feedback_body = "\n".join([
        "New DartHawk Feedback Submission",
        "",
        f"Submitted At: {submitted_at}",
        f"OS: {feedback_os}",
        f"Component: {feedback_component}",
        f"SR Number: {feedback_sr_number or 'Not provided'}",
        f"DART File Name: {feedback_dart_file_name or 'Not provided'}",
        f"Attachments: {len(attachments)} file(s)",
        "",
        "Issue Description:",
        feedback_issue,
    ])
    subject = f"[DartHawk Feedback] {feedback_component} | {feedback_os} | {submitted_at}"

    try:
        send_feedback_email(mail_config, subject, feedback_body, attachments)
    except Exception as exc:
        return jsonify({"error": f"Failed to send feedback email: {exc}"}), 500

    return jsonify({"message": "Feedback submitted successfully."}), 200


def wait_for_port_to_be_available(host, port, timeout_seconds=8.0, poll_interval=0.2):
    deadline = time.time() + max(timeout_seconds, 0.0)
    while time.time() <= deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.35)
            if sock.connect_ex((host, port)) != 0:
                return True
        time.sleep(max(poll_interval, 0.05))
    return False


def select_available_port(host, preferred_port, max_attempts=25):
    port = int(preferred_port)
    for _ in range(max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                port += 1
    raise RuntimeError(
        f"No available port found starting from {preferred_port} (attempted {max_attempts} ports)."
    )


def terminate_other_darthawk_instances():
    current_pid = os.getpid()

    try:
        ps_output = subprocess.check_output(["ps", "-ax", "-o", "pid=,command="], text=True)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return

    for row in ps_output.splitlines():
        text = row.strip()
        if not text:
            continue

        parts = text.split(None, 1)
        if not parts:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue

        command = parts[1] if len(parts) > 1 else ""
        normalized_command = command.lower()

        if pid == current_pid:
            continue
        if "darthawk.py" not in normalized_command:
            continue
        if "python" not in normalized_command and "gunicorn" not in normalized_command:
            continue

        try:
            os.kill(pid, 15)
        except OSError:
            continue

if __name__ == '__main__':
    host = os.environ.get("DARTHAWK_HOST", "127.0.0.1")
    preferred_port = int(os.environ.get("DARTHAWK_PORT", "5000"))
    auto_open_browser = os.environ.get("DARTHAWK_OPEN_BROWSER", "1").strip().lower() not in {
        "0", "false", "no"
    }

    terminate_other_darthawk_instances()
    wait_for_port_to_be_available(host, preferred_port)

    try:
        port = select_available_port(host, preferred_port)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    def open_browser():
        webbrowser.open_new(f"http://{host}:{port}")

    print("=============================================")
    print("   Starting DartHawk Analysis Tool...        ")
    print(f"   Open your browser at: http://{host}:{port}")
    if port != preferred_port:
        print(f"   Note: Port {preferred_port} was busy, using {port} instead")
    print("=============================================")
    # Open the UI automatically after the server starts.
    if auto_open_browser:
        Timer(1.0, open_browser).start()
    # Run server
    app.run(debug=True, use_reloader=False, host=host, port=port)
