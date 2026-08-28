"""Build the ATLAS -> BDB migration deck.

Kept as a script rather than a one-off so the deck can be regenerated when the
plan changes - a slide that disagrees with docs/BDB_MIGRATION_PLAN.md is worse
than no slide.
"""
from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

OUT = Path("/Users/amarora2/Documents/Atlas/ATLAS-BDB-Migration-Plan.pptx")

INK = RGBColor(0x0F, 0x17, 0x2A)
MUTED = RGBColor(0x55, 0x62, 0x7A)
ACCENT = RGBColor(0x00, 0x6C, 0xB5)
GOOD = RGBColor(0x0F, 0x7B, 0x55)
WARN = RGBColor(0xB4, 0x54, 0x09)
BAD = RGBColor(0xB3, 0x26, 0x1E)
RULE = RGBColor(0xD8, 0xDE, 0xE8)
PANEL = RGBColor(0xF4, 0xF7, 0xFB)

W, H = Inches(13.333), Inches(7.5)
MARGIN = Inches(0.72)
BODY_W = W - 2 * MARGIN


def _text(frame, runs, size=15, colour=INK, space_after=7, bullet_gap=0):
    """One paragraph per (text, bold, colour) triple."""
    frame.word_wrap = True
    first = True
    for item in runs:
        text, bold, colour_override = (item + (None,))[:3] if len(item) < 3 else item
        para = frame.paragraphs[0] if first else frame.add_paragraph()
        first = False
        para.space_after = Pt(space_after)
        para.space_before = Pt(bullet_gap)
        run = para.add_run()
        run.text = text
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.color.rgb = colour_override or colour
        run.font.name = "Calibri"
    return frame


def _slide(prs, title, kicker=None):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    box = slide.shapes.add_textbox(MARGIN, Inches(0.46), BODY_W, Inches(0.62))
    _text(box.text_frame, [(title, True)], size=30)
    top = Inches(1.12)
    if kicker:
        sub = slide.shapes.add_textbox(MARGIN, Inches(1.06), BODY_W, Inches(0.4))
        _text(sub.text_frame, [(kicker, False)], size=14, colour=MUTED)
        top = Inches(1.52)
    line = slide.shapes.add_shape(1, MARGIN, top, BODY_W, Emu(9525))
    line.fill.solid()
    line.fill.fore_color.rgb = RULE
    line.line.fill.background()
    line.shadow.inherit = False
    return slide, top + Inches(0.26)


def _panel(slide, left, top, width, height, fill=PANEL):
    shape = slide.shapes.add_shape(5, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    shape.line.color.rgb = RULE
    shape.line.width = Pt(0.75)
    shape.shadow.inherit = False
    return shape


def _table(slide, top, headers, rows, widths, height=Inches(0.34)):
    cols = len(headers)
    total = sum(widths)
    shape = slide.shapes.add_table(len(rows) + 1, cols, MARGIN, top, Inches(total), height).table
    for index, width in enumerate(widths):
        shape.columns[index].width = Inches(width)
    for index, head in enumerate(headers):
        cell = shape.cell(0, index)
        cell.text = head
        para = cell.text_frame.paragraphs[0]
        para.runs[0].font.size = Pt(13)
        para.runs[0].font.bold = True
        para.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.fill.solid()
        cell.fill.fore_color.rgb = ACCENT
    for r, row in enumerate(rows, start=1):
        for c, value in enumerate(row):
            cell = shape.cell(r, c)
            cell.text = str(value)
            para = cell.text_frame.paragraphs[0]
            para.runs[0].font.size = Pt(12)
            para.runs[0].font.color.rgb = INK
            cell.fill.solid()
            cell.fill.fore_color.rgb = RGBColor(0xFF, 0xFF, 0xFF) if r % 2 else PANEL
    return shape


def build() -> None:
    prs = Presentation()
    prs.slide_width, prs.slide_height = W, H

    # ---- 1. Title --------------------------------------------------------
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    band = slide.shapes.add_shape(1, Emu(0), Inches(2.5), W, Inches(1.9))
    band.fill.solid()
    band.fill.fore_color.rgb = ACCENT
    band.line.fill.background()
    band.shadow.inherit = False
    box = slide.shapes.add_textbox(MARGIN, Inches(2.72), BODY_W, Inches(1.5))
    _text(box.text_frame, [
        ("Project ATLAS \u2192 BDB", True, RGBColor(0xFF, 0xFF, 0xFF)),
    ], size=40)
    sub = slide.shapes.add_textbox(MARGIN, Inches(3.52), BODY_W, Inches(0.8))
    _text(sub.text_frame, [
        ("Step-by-step migration plan", False, RGBColor(0xE6, 0xF1, 0xFA)),
    ], size=19)
    foot = slide.shapes.add_textbox(MARGIN, Inches(4.75), BODY_W, Inches(0.9))
    _text(foot.text_frame, [
        ("Cisco Secure Access \u2014 TAC Diagnostics", False, MUTED),
        ("Assessment based on a measured Phase 0 spike, not an estimate", False, MUTED),
    ], size=13)

    # ---- 2. Verdict ------------------------------------------------------
    slide, top = _slide(prs, "Verdict", "Both risks that could have stopped this are now closed")
    cards = [
        ("Packet parsing\nwithout tshark", "CLOSED", "dpkt replaces tshark and runs\n2.5\u20139.6\u00d7 faster, with parity on\nstructure, headers and flow discovery.", GOOD),
        ("UI hosting\non BDB", "CLOSED", "BDB serves task files as a CDN and\nruns full ES-module JavaScript.\nAtlas is vanilla JS \u2014 near drop-in.", GOOD),
        ("TLS parsing", "REMAINING", "Every Gate E failure traces here.\nBounded, well-understood work.", WARN),
    ]
    width = Inches(3.86)
    for index, (title, tag, body, colour) in enumerate(cards):
        left = MARGIN + index * (width + Inches(0.18))
        _panel(slide, left, top, width, Inches(2.15))
        box = slide.shapes.add_textbox(left + Inches(0.22), top + Inches(0.18), width - Inches(0.44), Inches(1.8))
        _text(box.text_frame, [
            (tag, True, colour),
            (title.replace("\n", " "), True, INK),
            (body.replace("\n", " "), False, MUTED),
        ], size=13)

    box = slide.shapes.add_textbox(MARGIN, top + Inches(2.55), BODY_W, Inches(1.5))
    _text(box.text_frame, [
        ("Migrate it.", True, INK),
        ("The analysis layer \u2014 atlas_core, where the value actually sits \u2014 has no framework imports and ports untouched. "
         "What is left is a TLS parser, a template rewrite, and mechanical task decomposition.", False, MUTED),
        ("This is a re-platforming with a real rewrite in the middle, not a lift-and-shift.", True, WARN),
    ], size=15)

    # ---- 3. What Atlas is today -----------------------------------------
    slide, top = _slide(prs, "What ATLAS is today", "~35,000 lines of application code, in production use for TAC escalations")
    _table(slide, top,
           ["Component", "Role", "Stack"],
           [["DartHawk", "DART bundle analysis \u2014 what the endpoint was configured to do", "Flask + Jinja2, ~9k Py / 7.5k JS"],
            ["Capture Inspector", "PCAP / HAR analysis \u2014 what it actually did on the wire", "FastAPI, ~5.5k Py"],
            ["atlas_core", "Correlation, flow joins, multi-vantage path stitching", "Pure Python, ~3k"],
            ["Web shell", "One origin over both engines", "FastAPI + a2wsgi bridge"],
            ["Frontend", "Vanilla JS, no build step, Tailwind via CDN", "~18,600 lines"]],
           [2.5, 6.1, 3.3])
    box = slide.shapes.add_textbox(MARGIN, top + Inches(2.6), BODY_W, Inches(1.0))
    _text(box.text_frame, [
        ("The division that matters: the bundle is a declaration, the capture is a measurement. "
         "ATLAS reports where the two disagree \u2014 which neither artefact can establish alone.", False, MUTED),
    ], size=14)

    # ---- 4. What BDB provides -------------------------------------------
    slide, top = _slide(prs, "What BDB provides", "Verified against the API docs, the python3.13 package list and the Full Stack tutorial")
    _table(slide, top,
           ["Capability", "Mechanism"],
           [["Frontend hosting", "Task-root files served as a CDN at /app/<task> and /app_dev/<task>"],
            ["Custom JS / CSS", "Full ES modules. Harbor UI kit available. Nothing sanitised"],
            ["Backend calls", "POST /api/v2/jobs/<task>, sync or async. Same-origin bdb_cookie auth"],
            ["File upload", "POST /api/v2/files — multipart/form-data, 10 GB per file"],
            ["Session state", "Session folder persists across runs, addressed by sub_path"],
            ["TAC integration", "Pull a case attachment straight into the session folder by SR id"],
            ["Code sync", "Every task has an auto-created GitHub repo + pushpull endpoint"],
            ["Packages", "dpkt, scapy, haralyzer, python-evtx, lxml, pandas, plotly"]],
           [3.1, 8.8])
    box = slide.shapes.add_textbox(MARGIN, top + Inches(3.15), BODY_W, Inches(0.8))
    _text(box.text_frame, [
        ("Absent: Flask, FastAPI and a2wsgi. This is the single reason the web layer cannot come across unchanged.", True, BAD),
    ], size=14)

    # ---- 5. Phase 0 evidence --------------------------------------------
    slide, top = _slide(prs, "Phase 0 \u2014 what was measured", "A dpkt reader built and compared against tshark over six real captures")
    _table(slide, top,
           ["Gate", "What it checks", "Result"],
           [["A \u2014 Structural", "Same flows discovered", "PASS on 4 of 6 after fixes"],
            ["B \u2014 Headers", "Addresses, ports, ISN, byte counts", "100% on 4 of 6"],
            ["C \u2014 TLS", "SNI, version, ALPN", "FAILS \u2014 the remaining work"],
            ["D \u2014 Derived", "Retransmits, zero-windows, RTT", "97.5\u2013100%"],
            ["E \u2014 Conclusions", "Do verdicts change when the reader is swapped?", "Path stitching invariant; correlation fails on TLS"],
            ["Performance", "Throughput vs tshark", "2.5\u20139.6\u00d7 FASTER"]],
           [2.4, 5.6, 3.9])
    box = slide.shapes.add_textbox(MARGIN, top + Inches(2.85), BODY_W, Inches(1.4))
    _text(box.text_frame, [
        ("Four real defects found and fixed during the spike:", True, INK),
        ("Flow orientation (absent a handshake, the lower port is the listener)  \u00b7  port reuse splitting  \u00b7  "
         "gzipped captures  \u00b7  an idna decode that silently swallowed every SNI.", False, MUTED),
    ], size=13)

    # ---- 6. Target architecture -----------------------------------------
    slide, top = _slide(prs, "Target architecture", "Start as ONE task with an action input; split later if needed")
    _table(slide, top,
           ["ATLAS today", "On BDB", "Effort"],
           [["FastAPI web shell", "Gone \u2014 BDB serves the frontend", "Delete"],
            ["Capture Inspector static HTML/JS/CSS", "Copy to task root", "Drop-in"],
            ["Shell assets, design tokens", "Copy to task root", "Drop-in"],
            ["atlas_core (correlation, path)", "Unchanged \u2014 no framework imports", "None"],
            ["DartHawk Jinja2 + Flask", "Static HTML, rendering moved client-side", "REWRITE"],
            ["Routes /upload, /flows, /flow", "action values on the task", "Mechanical"],
            ["In-memory capture store", "Session folder + subPath", "Small"],
            ["Tailwind via public CDN", "Vendor as a task file", "Small \u2014 fixes an existing bug"],
            ["tshark", "dpkt", "TLS parser outstanding"]],
           [4.3, 5.2, 2.4])

    # ---- 7. The steps ----------------------------------------------------
    slide, top = _slide(prs, "Step-by-step plan", "Sequenced so the unknowns die earliest")
    steps = [
        ("0", "Vertical slice", "DART bundle in \u2192 health snapshot rendered. No tshark needed. Exercises upload, task invocation, CDN frontend, JSON round-trip and rendering all at once.", ACCENT),
        ("1", "Finish the packet layer", "TLS parser with segment reassembly. Re-run Gate E until correlation is invariant. Fix the gzip capture. Prove the ISN join.", WARN),
        ("2", "Split backend into task actions", "analyze_bundle, capture_flows, flow_detail, correlate, path_stitch. Boundaries already exist as routes.", MUTED),
        ("3", "Frontend port", "Copy static assets, vendor Tailwind, rewrite DartHawk templates client-side, repoint fetch calls at the jobs API.", MUTED),
        ("4", "State and TAC integration", "Session folder wiring, then pull bundles straight off a case by SR id.", MUTED),
    ]
    y = top
    for number, title, body, colour in steps:
        chip = slide.shapes.add_shape(9, MARGIN, y, Inches(0.46), Inches(0.46))
        chip.fill.solid()
        chip.fill.fore_color.rgb = colour
        chip.line.fill.background()
        chip.shadow.inherit = False
        chip.text_frame.text = number
        para = chip.text_frame.paragraphs[0]
        para.alignment = PP_ALIGN.CENTER
        para.runs[0].font.size = Pt(16)
        para.runs[0].font.bold = True
        para.runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        box = slide.shapes.add_textbox(MARGIN + Inches(0.66), y - Inches(0.04), BODY_W - Inches(0.7), Inches(0.9))
        _text(box.text_frame, [(title, True, INK), (body, False, MUTED)], size=13, space_after=2)
        y += Inches(1.02)

    # ---- 8. Task configuration ------------------------------------------
    slide, top = _slide(prs, "Task configuration", "What to set when creating the BDB task")
    _table(slide, top,
           ["Field", "Value", "Why"],
           [["name", "atlas", "Becomes the app URL: /app_dev/atlas"],
            ["service type", "python3.13", "Has dpkt, scapy, python-evtx, haralyzer"],
            ["public", "CHECKED", "Required \u2014 the web app will not serve otherwise"],
            ["contributors", "TAC teammates", "Who else may run it"],
            ["inputs", "Set via API, not by hand", "bdb.json is not directly editable"]],
           [2.4, 3.4, 6.1])
    box = slide.shapes.add_textbox(MARGIN, top + Inches(2.25), BODY_W, Inches(1.6))
    _text(box.text_frame, [
        ("Inputs for the slice", True, INK),
        ("action \u2014 select: analyze_bundle | capture_flows | flow_detail | correlate", False, MUTED),
        ("bundle \u2014 inputFile, the DART ZIP", False, MUTED),
        ("sub_path \u2014 text, optional, points at a file already in the session folder", False, MUTED),
    ], size=13, space_after=4)

    # ---- 9. Code workflow ------------------------------------------------
    slide, top = _slide(prs, "Moving the code", "Normal git \u2014 not copy-paste into a web editor")
    flow = [
        "Create the task in BDB",
        "BDB auto-provisions a GitHub repo",
        "Grant repo access, then clone",
        "Port code, commit, push",
        "pushpull/pull syncs into BDB",
        "Save \u2192 /app_dev  \u00b7  Deploy \u2192 /app",
    ]
    y = top + Inches(0.1)
    for index, step in enumerate(flow):
        _panel(slide, MARGIN, y, Inches(5.6), Inches(0.5), PANEL if index % 2 == 0 else RGBColor(0xFF, 0xFF, 0xFF))
        box = slide.shapes.add_textbox(MARGIN + Inches(0.2), y + Inches(0.08), Inches(5.3), Inches(0.4))
        _text(box.text_frame, [(f"{index + 1}.  {step}", False, INK)], size=13)
        y += Inches(0.62)

    _panel(slide, MARGIN + Inches(6.0), top + Inches(0.1), Inches(5.9), Inches(2.4))
    box = slide.shapes.add_textbox(MARGIN + Inches(6.24), top + Inches(0.32), Inches(5.5), Inches(2.1))
    _text(box.text_frame, [
        ("Two separate repositories", True, INK),
        ("amarora2_cisco/Atlas \u2014 stays the upstream source of truth.", False, MUTED),
        ("The BDB task repo \u2014 a deployment target, populated with the ported subset.", False, MUTED),
        ("Whether they stay in sync, or the BDB repo becomes the real home, is a decision to make deliberately \u2014 but not before the slice proves out.", False, MUTED),
    ], size=13)

    # ---- 10. Risks -------------------------------------------------------
    slide, top = _slide(prs, "Open risks and unknowns", "Stated plainly so none of these arrive as a surprise")
    risks = [
        ("TLS keylog decryption is lost", "tshark uses the full Wireshark TLS stack. Nothing in pure Python comes close. Confirm this is acceptable now, not mid-rewrite.", BAD),
        ("The ISN cross-vantage join has never executed", "proved_hops = 0 for both readers \u2014 the test captures share no traffic. It is the linchpin of the path claim and is still unproven.", BAD),
        ("Job execution timeout unconfirmed", "The last open unknown. dpkt running 2.5–9.6× faster than tshark makes this unlikely to bite, but it is not yet measured.", WARN),
        ("One gzipped capture yields zero flows", "Opens and reports Ethernet encapsulation correctly, but produces nothing. Unresolved.", WARN),
        ("DartHawk template rewrite", "The only genuine frontend rewrite. Bounded, but it is real work rather than a copy.", WARN),
    ]
    y = top
    for title, body, colour in risks:
        bar = slide.shapes.add_shape(1, MARGIN, y, Inches(0.07), Inches(0.78))
        bar.fill.solid()
        bar.fill.fore_color.rgb = colour
        bar.line.fill.background()
        bar.shadow.inherit = False
        box = slide.shapes.add_textbox(MARGIN + Inches(0.24), y - Inches(0.03), BODY_W - Inches(0.3), Inches(0.85))
        _text(box.text_frame, [(title, True, INK), (body, False, MUTED)], size=13, space_after=1)
        y += Inches(0.92)

    # ---- 11. Next actions ------------------------------------------------
    slide, top = _slide(prs, "Next actions", None)
    _table(slide, top,
           ["#", "Action", "Owner"],
           [["1", "Create the BDB task \u2014 python3.13, public checked", "Amit"],
            ["2", "Confirm repo access and share the clone URL", "Amit"],
            ["3", "Decide: is losing TLS keylog decryption acceptable?", "Amit"],
            ["4", "Build the vertical slice — bundle in, snapshot out", "Agent"],
            ["5", "TLS parser, then re-run Gate E to invariance", "Agent"],
            ["6", "Source a same-traffic capture pair to prove the ISN join", "Amit / Agent"]],
           [0.7, 8.6, 2.6])
    box = slide.shapes.add_textbox(MARGIN, top + Inches(2.85), BODY_W, Inches(1.0))
    _text(box.text_frame, [
        ("Full detail: docs/BDB_MIGRATION_PLAN.md in the ATLAS repository (commit 6f56806).", False, MUTED),
    ], size=13)

    prs.save(OUT)
    print(f"saved: {OUT}")
    print(f"slides: {len(prs.slides.__iter__.__self__._sldIdLst)}")


if __name__ == "__main__":
    build()
