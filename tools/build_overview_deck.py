"""Build the ATLAS overview deck: what the tool does, use cases, screenshots.

Screenshots come from docs/deck-img/, captured from a real run against the
bundle and capture in Logs/. Regenerate the deck whenever those are refreshed.
"""
from __future__ import annotations

import struct
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.util import Emu, Inches, Pt

OUT = Path("/Users/amarora2/Documents/Atlas/ATLAS-Overview.pptx")
SHOTS = Path("/Users/amarora2/Documents/Atlas/docs/deck-img")

INK = RGBColor(0x0F, 0x17, 0x2A)
MUTED = RGBColor(0x55, 0x62, 0x7A)
ACCENT = RGBColor(0x00, 0x6C, 0xB5)
GOOD = RGBColor(0x0F, 0x7B, 0x55)
WARN = RGBColor(0xB4, 0x54, 0x09)
RULE = RGBColor(0xD8, 0xDE, 0xE8)
PANEL = RGBColor(0xF4, 0xF7, 0xFB)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

W, H = Inches(13.333), Inches(7.5)
MARGIN = Inches(0.72)
BODY_W = W - 2 * MARGIN


def _text(frame, runs, size=15, colour=INK, space_after=7):
    frame.word_wrap = True
    first = True
    for item in runs:
        text, bold = item[0], item[1]
        override = item[2] if len(item) > 2 else None
        para = frame.paragraphs[0] if first else frame.add_paragraph()
        first = False
        para.space_after = Pt(space_after)
        run = para.add_run()
        run.text = text
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.color.rgb = override or colour
        run.font.name = "Calibri"
    return frame


def _slide(prs, title, kicker=None):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    box = slide.shapes.add_textbox(MARGIN, Inches(0.42), BODY_W, Inches(0.62))
    _text(box.text_frame, [(title, True)], size=28)
    top = Inches(1.06)
    if kicker:
        sub = slide.shapes.add_textbox(MARGIN, Inches(1.00), BODY_W, Inches(0.4))
        _text(sub.text_frame, [(kicker, False)], size=13.5, colour=MUTED)
        top = Inches(1.44)
    line = slide.shapes.add_shape(1, MARGIN, top, BODY_W, Emu(9525))
    line.fill.solid()
    line.fill.fore_color.rgb = RULE
    line.line.fill.background()
    line.shadow.inherit = False
    return slide, top + Inches(0.24)


def _panel(slide, left, top, width, height, fill=PANEL):
    shape = slide.shapes.add_shape(5, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    shape.line.color.rgb = RULE
    shape.line.width = Pt(0.75)
    shape.shadow.inherit = False
    return shape


def _table(slide, top, headers, rows, widths, size=12):
    shape = slide.shapes.add_table(
        len(rows) + 1, len(headers), MARGIN, top, Inches(sum(widths)), Inches(0.32)
    ).table
    for index, width in enumerate(widths):
        shape.columns[index].width = Inches(width)
    for index, head in enumerate(headers):
        cell = shape.cell(0, index)
        cell.text = head
        run = cell.text_frame.paragraphs[0].runs[0]
        run.font.size = Pt(size + 1)
        run.font.bold = True
        run.font.color.rgb = WHITE
        cell.fill.solid()
        cell.fill.fore_color.rgb = ACCENT
    for r, row in enumerate(rows, start=1):
        for c, value in enumerate(row):
            cell = shape.cell(r, c)
            cell.text = str(value)
            run = cell.text_frame.paragraphs[0].runs[0]
            run.font.size = Pt(size)
            run.font.color.rgb = INK
            cell.fill.solid()
            cell.fill.fore_color.rgb = WHITE if r % 2 else PANEL
    return shape


def _notes(slide, text):
    slide.notes_slide.notes_text_frame.text = text
    return slide


def _png_size(path: Path) -> tuple[int, int]:
    """Width and height from the PNG IHDR, so no image library is needed."""
    return struct.unpack(">II", path.read_bytes()[16:24])


def _shot2(prs, title, kicker, pairs, highlights, note, strip=None):
    """Screenshots side by side, with captions and shared highlights.

    Each pair is (image, caption) or (image, caption, crop_right).
    ``strip`` replaces the highlights list with one full-width image.
    """
    slide, top = _slide(prs, title, kicker)
    gap = Inches(0.34)
    columns = len(pairs)
    col_w = (BODY_W - gap * (columns - 1)) // columns
    if strip:
        strip_w = Inches(9.9)
        strip_px_w, strip_px_h = _png_size(SHOTS / strip)
        strip_h = Emu(int(strip_w * strip_px_h / strip_px_w))
        note_h = strip_h + Inches(0.1)
    else:
        note_h = Inches(0.26) * (len(highlights) + 1) + Inches(0.12)
    max_img_h = H - top - note_h - Inches(0.62)

    for index, pair in enumerate(pairs):
        image, caption = pair[0], pair[1]
        crop_right = pair[2] if len(pair) > 2 else 0.0
        path = SHOTS / image
        px_w, px_h = _png_size(path)
        aspect = px_w * (1 - crop_right) / px_h
        img_w, img_h = col_w, Emu(int(col_w / aspect))
        if img_h > max_img_h:
            img_h = max_img_h
            img_w = Emu(int(img_h * aspect))
        left = MARGIN + index * (col_w + gap) + (col_w - img_w) // 2
        pic = slide.shapes.add_picture(
            str(path), left, top + (max_img_h - img_h) // 2, width=img_w, height=img_h
        )
        pic.crop_right = crop_right
        cap = slide.shapes.add_textbox(
            MARGIN + index * (col_w + gap), top + max_img_h + Inches(0.06),
            col_w, Inches(0.32)
        )
        _text(cap.text_frame, [(caption, True, ACCENT)], size=12)

    strip_top = top + max_img_h + Inches(0.44)
    if strip:
        slide.shapes.add_picture(
            str(SHOTS / strip), MARGIN + (BODY_W - strip_w) // 2, strip_top,
            width=strip_w, height=strip_h
        )
    else:
        box = slide.shapes.add_textbox(MARGIN, strip_top, BODY_W, note_h)
        runs = [("Highlights", True, ACCENT)]
        runs += [("\u2022  " + h, False, INK) for h in highlights]
        _text(box.text_frame, runs, size=13, space_after=4)
    return _notes(slide, note)


def _shot(prs, title, kicker, image, highlights, note):
    """Screenshot plus a few short highlights. Tall shots sit beside the text."""
    slide, top = _slide(prs, title, kicker)
    path = SHOTS / image
    px_w, px_h = _png_size(path)
    aspect = px_w / px_h
    avail_h = H - top - Inches(0.45)

    # A very tall capture shrunk to fit becomes an unreadable sliver; trim instead.
    crop_bottom = 0.0
    if aspect < 0.62:
        crop_bottom = 1 - aspect / 0.62
        aspect = 0.62

    runs = [("Highlights", True, ACCENT)]
    runs += [("\u2022  " + h, False, INK) for h in highlights]

    if aspect < 1.15:
        img_h = avail_h
        img_w = Emu(int(img_h * aspect))
        if img_w > Inches(6.4):
            img_w = Inches(6.4)
            img_h = Emu(int(img_w / aspect))
        pic = slide.shapes.add_picture(str(path), MARGIN, top, width=img_w, height=img_h)
        pic.crop_bottom = crop_bottom
        left = MARGIN + img_w + Inches(0.4)
        box = slide.shapes.add_textbox(left, top + Inches(0.1), W - left - MARGIN, avail_h)
        _text(box.text_frame, runs, size=14, space_after=9)
    else:
        note_h = Inches(0.3) * (len(highlights) + 1) + Inches(0.2)
        img_w = BODY_W
        img_h = Emu(int(img_w / aspect))
        if img_h > avail_h - note_h:
            img_h = avail_h - note_h
            img_w = Emu(int(img_h * aspect))
        left = MARGIN + (BODY_W - img_w) // 2
        pic = slide.shapes.add_picture(str(path), left, top, width=img_w, height=img_h)
        pic.crop_bottom = crop_bottom
        box = slide.shapes.add_textbox(MARGIN, top + img_h + Inches(0.14), BODY_W, note_h)
        _text(box.text_frame, runs, size=13, space_after=4)
    return _notes(slide, note)


def build() -> None:
    prs = Presentation()
    prs.slide_width, prs.slide_height = W, H

    # 1 -- Title -----------------------------------------------------------
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    band = slide.shapes.add_shape(1, Emu(0), Inches(2.4), W, Inches(2.0))
    band.fill.solid()
    band.fill.fore_color.rgb = ACCENT
    band.line.fill.background()
    band.shadow.inherit = False
    box = slide.shapes.add_textbox(MARGIN, Inches(2.62), BODY_W, Inches(1.5))
    _text(box.text_frame, [("Project ATLAS", True, WHITE)], size=44)
    sub = slide.shapes.add_textbox(MARGIN, Inches(3.48), BODY_W, Inches(0.9))
    _text(sub.text_frame, [
        ("Overview, use cases and screenshots", False, RGBColor(0xE6, 0xF1, 0xFA)),
    ], size=19)
    foot = slide.shapes.add_textbox(MARGIN, Inches(4.75), BODY_W, Inches(1.0))
    _text(foot.text_frame, [
        ("Unified Cisco endpoint and network diagnostics", False, MUTED),
        ("Cisco Secure Access \u2014 TAC Diagnostics", False, MUTED),
    ], size=13)
    _notes(slide, "Title slide: ATLAS is one tool that analyses a Cisco endpoint's "
                  "configuration and its actual network traffic together.")

    # 2 -- What it is ------------------------------------------------------
    slide, top = _slide(
        prs, "What ATLAS is",
        "One web tool that diagnoses an endpoint from both sides at once",
    )
    cards = [
        ("THE DECLARATION", "DART bundle",
         "What the endpoint was configured to do, and what its software reported.", ACCENT),
        ("THE MEASUREMENT", "Packet capture / HAR",
         "What the endpoint actually did on the wire.", ACCENT),
        ("THE ANSWER", "Where the two disagree",
         "A finding neither artefact can produce on its own.", GOOD),
    ]
    width = Inches(3.86)
    for index, (tag, name, body, colour) in enumerate(cards):
        left = MARGIN + index * (width + Inches(0.18))
        _panel(slide, left, top, width, Inches(2.0))
        box = slide.shapes.add_textbox(
            left + Inches(0.22), top + Inches(0.2), width - Inches(0.44), Inches(1.7)
        )
        _text(box.text_frame, [
            (tag, True, colour), (name, True, INK), (body, False, MUTED),
        ], size=13)

    box = slide.shapes.add_textbox(MARGIN, top + Inches(2.4), BODY_W, Inches(1.6))
    _text(box.text_frame, [
        ("Evidence or nothing.", True, INK),
        ("Every finding cites what produced it. Where the input cannot answer a "
         "question, ATLAS says so instead of guessing.", False, MUTED),
    ], size=15)
    _notes(slide, "The product thesis: the bundle says what was configured, the capture "
                  "says what happened, and the disagreement between them is the finding.")

    # 3 -- What it can do --------------------------------------------------
    slide, top = _slide(prs, "What it can do", "All of this is live today")
    _table(slide, top,
           ["Capability", "In short"],
           [["DART bundle analysis", "8 ZTA / Duo checks from one upload, plus an "
             "interpreted ZTA Health Snapshot"],
            ["Capture & HAR analysis", "69 detectors \u2014 TLS interception, certificates, "
             "DNS, proxy blocks, QUIC, MTU, latency"],
            ["Per-connection story", "DNS \u2192 TCP \u2192 TUNNEL \u2192 TLS \u2192 HTTP "
             "\u2192 DATA, each layer with its own verdict"],
            ["Steering verification", "Which hosts were steered through the agent and which "
             "went direct \u2014 measured on the wire"],
            ["Cross-artefact correlation", "Joins bundle + capture + HAR into one account of "
             "a session, on connection identity"],
            ["End-to-end path", "Stitches captures from client, proxy, firewall and resource "
             "into one hop chain"],
            ["One report", "Everything analysed, exported together with the filenames it "
             "came from"]],
           [3.4, 8.4])
    _notes(slide, "The seven things ATLAS does today, from bundle checks through to "
                  "multi-capture path stitching \u2014 all of it shipping, none of it roadmap.")

    # 4 -- Use cases at a glance -------------------------------------------
    slide, top = _slide(prs, "Use cases at a glance", "The questions it is built to answer")
    _table(slide, top,
           ["The complaint", "What ATLAS answers", "Needs"],
           [["\u201cThe app is slow through Secure Access\u201d",
             "At which layer the time went, and whether the agent logged a reason",
             "Capture + HAR + bundle"],
            ["\u201cSSO / domain logon broke after ZTA\u201d",
             "Whether the tunnel was up and internal name resolution answered at that moment",
             "Bundle (+ capture)"],
            ["\u201cThe client will not enrol\u201d",
             "Which attempts failed, and the fix for the auth type actually in use",
             "Bundle only"],
            ["\u201cIs traffic going where policy says?\u201d",
             "Per-host steered / direct / not determined, measured on the wire",
             "Capture + bundle"],
            ["\u201cWhere in the path is the loss?\u201d",
             "Which leg of a multi-hop path shows it, with proved hops counted separately",
             "Captures from each point"]],
           [3.6, 5.9, 2.4], size=11.5)
    _notes(slide, "The five escalations ATLAS is built for, and which artefacts each one "
                  "needs \u2014 note that enrolment issues need only the bundle.")

    # 5-13 -- Screenshots --------------------------------------------------
    _shot(prs, "One evidence step", "Drop in a capture, a HAR and a DART bundle \u2014 one Analyze button",
          "01-evidence.png", [
              "All three artefacts analysed from a single click.",
              "Correlation runs automatically once two or more are loaded.",
              "Optional context fields sharpen the analysis; none are required.",
          ],
          "The starting point: one upload step takes all three artefacts and one button "
          "analyses them together.")

    _shot(prs, "ZTA Health Snapshot", "The bundle read at a glance",
          "13-zta-snapshot.png", [
              "Verdict, health score and how many checks need attention.",
              "Top destinations shown, so a flow count says which hosts it is about.",
              "Problems first; healthy checks folded into one row.",
          ],
          "The bundle's headline view \u2014 a verdict and score instead of eight raw check "
          "outputs to read through.")

    _shot(prs, "Every finding, in the same shape", "User Pause \u2014 the finding that explains an \u201capp not working\u201d report",
          "15-zta-userpause.png", [
              "Summary, what it means, impact and next steps \u2014 no clicking.",
              "Written for an engineer to act on, not a log dump.",
          ],
          "Every issue is presented the same way, so an engineer always knows where to "
          "find the impact and the next step.")

    _shot2(prs, "Enrollment \u2014 success and failure",
           "Every enrollment attempt in the bundle, with the auto-detected auth type",
           [("18-enroll-success.png", "Healthy client \u2014 1 attempt, all ok"),
            ("21-enroll-mixed.png", "Problem client \u2014 4 attempts, 2 ok \u00b7 2 failed"),
            ("23-flow-ladder-enroll-fail.png",
             "Ladder for a failed attempt \u2014 ends in failure", 0.42)],
           ["Certificate-based vs SAML-based is detected from the logs \u2014 nothing to choose.",
            "Each attempt gets a timestamp, an identifier and a Success / Failure verdict.",
            "Here the cause was: none of the 5 client certificates matched the enrolment policy.",
            "The failed ladder stops at \u2018Enrollment Ended (failure)\u2019 \u2014 no bootstrap, "
            "no device registration, no ACME exchange ever happened.",
            "\u2018Open flow\u2019 takes any attempt, passed or failed, straight into its ladder."],
           "Enrollment troubleshooting needs only the bundle \u2014 ATLAS lists every attempt, "
           "draws the failed one as a ladder, and highlights the exact log lines that "
           "explain it: none of the five client certificates matched the enrolment policy, "
           "so bootstrap failed after 38 ms.",
           strip="24-enroll-fail-logs.png")

    _shot(prs, "Plain-English summary first", "The capture engine leads with what it means",
          "02-exec-summary.png", [
              "240 connections, 7 DNS lookups, 9 failed browser requests, 7 connections with a problem.",
              "Names the layer, states the impact, suggests the action.",
          ],
          "The capture side opens in plain English before any protocol detail, so a "
          "non-specialist can read the verdict.")

    _shot(prs, "Findings, most severe first", "Each one carries the evidence that produced it",
          "03-findings.png", [
              "Severity counts and a stated confidence level.",
              "Interception, proxy blocks, QUIC bypass, MTU, latency and more.",
              "Every card has a How to fix drawer.",
          ],
          "The detector output, ranked by severity, with the raw evidence string attached "
          "to each finding.")

    _shot(prs, "Flows and events in one table", "Capture flows and browser requests side by side",
          "04-flows.png", [
              "Worst first, filterable by domain or IP.",
              "Loopback flows tagged as the agent's local listener, so nothing looks odd.",
          ],
          "Packet flows and browser requests merged into a single timeline, so both views "
          "of the same failure sit together.")

    _shot(prs, "The connection story", "One flow, end to end \u2014 it names the layer that failed",
          "05-connection-story.png", [
              "TCP \u2713 connected in 0.1 ms.",
              "TLS \u2715 failed \u2014 ServerHello seen, then the server reset it.",
              "Conclusion states what is provable, and says when no reason was given.",
          ],
          "Drilling into one connection: ATLAS pinpoints the layer that failed rather than "
          "leaving the reader to decode packets.")

    _shot2(prs, "Flow ladder diagrams",
           "The Visual Flow Analyzer turns raw agent logs into a sequence diagram",
           [("19-flow-ladder-enroll.png", "Enrollment \u2014 bootstrap \u2192 device reg \u2192 DHA \u2192 ACME"),
            ("20-flow-ladder-spa.png", "Secure Private Access \u2014 one steered application flow")],
           ["Client on the left, Cisco Secure Access on the right; time runs down the page.",
            "Colour and direction show request, response, local processing or error.",
            "HTTP status and state transitions are read straight from the log line.",
            "Click any step for the raw log line it came from; export as SVG or PNG."],
           "Ladder diagrams replace log-reading: the whole transaction becomes one picture, "
           "and every step still cites its source line.")

    _shot(prs, "Hosts and DNS", "Every destination the client talked to",
          "06-hosts.png", [
              "33 hosts, 2 with issues, 1 TLS-intercepted.",
              "Interception is read from the certificate on the wire, not assumed.",
          ],
          "An inventory view: which destinations the client reached, and which of them "
          "were decrypted on the way.")

    _shot(prs, "Correlation across three artefacts", "One browsing session, joined",
          "09-corr-stats.png", [
              "19 hosts \u2014 18 steered, 1 direct, 0 not determined.",
              "385 intercepted flows, 5 tunnels matched, 162 requests, 9 failures.",
              "None of these numbers exist in any single artefact.",
          ],
          "The correlation layer's headline numbers \u2014 produced only because all three "
          "artefacts were analysed together.")

    _shot(prs, "Steering, measured on the wire", "What the configuration declared vs what actually happened",
          "10-corr-steering.png", [
              "Per host: Steered or Direct, with the evidence for that verdict.",
              "Two CDN hosts steered and failing every request \u2014 403 and 502.",
              "A directly-reached host beside them returned 200.",
          ],
          "Steering verification: proof from the wire of which hosts went through the agent, "
          "set against how they performed.")

    _shot(prs, "Browser failure tied to the packet flow", "The join neither artefact can make alone",
          "08-evidence-connects.png", [
              "The HAR knew the hostname and the status code.",
              "The capture knew the connection it travelled on.",
              "ATLAS reports both together, and names the flow.",
          ],
          "The clearest example of the whole idea: a browser error linked to the exact "
          "packet flow that carried it.")

    _shot(prs, "It says what it could not answer", "Printed on every run, not hidden",
          "12-corr-limits.png", [
              "Names the flows it refused to join, and why.",
              "A host absent from the agent's list is one it logged no problem for "
              "\u2014 not one known to have worked.",
          ],
          "ATLAS states its own blind spots on every run, so absence of a finding is never "
          "mistaken for a clean result.")

    # 14 -- Summary --------------------------------------------------------
    slide, top = _slide(prs, "In one page", None)
    _panel(slide, MARGIN, top, BODY_W, Inches(4.3))
    box = slide.shapes.add_textbox(
        MARGIN + Inches(0.32), top + Inches(0.3), BODY_W - Inches(0.64), Inches(3.8)
    )
    _text(box.text_frame, [
        ("One tool, three artefacts, one answer.", True, ACCENT),
        ("Give ATLAS a DART bundle, a packet capture and a browser HAR and it "
         "analyses all three from one Analyze button.", False, INK),
        ("", False, INK),
        ("\u2022  Was the endpoint configured to do what it did?", False, MUTED),
        ("\u2022  Which hosts were actually steered, and which were not?", False, MUTED),
        ("\u2022  Where in a multi-hop path did it break?", False, MUTED),
        ("", False, INK),
        ("And it is explicit about what it cannot see \u2014 which is what makes the "
         "rest worth trusting.", True, WARN),
    ], size=15, space_after=6)
    _notes(slide, "Closing summary: three artefacts in, one answer out, and an honest "
                  "statement of the limits.")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUT)
    print(f"wrote {OUT} ({len(prs.slides._sldIdLst)} slides)")


if __name__ == "__main__":
    build()
