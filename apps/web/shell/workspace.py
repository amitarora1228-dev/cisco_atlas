"""Compose both engines into one document - the unified ATLAS workspace.

A single analysis session usually involves more than one artifact: a DART bundle
from the endpoint, a packet capture from the wire, and sometimes a HAR from the
browser. Switching tools between them loses the thread, so ATLAS puts all of
them on one page.

This is possible without rewriting either frontend because the two are
accidentally compatible - verified, not assumed:

* 0 element-id collisions (156 ids in the bundle UI, 66 in the capture UI)
* 0 top-level JavaScript name collisions (1 vs 58)

So both engines' markup, styles and scripts can share one document, each keeping
its own renderer and behaviour. The shell supplies one header, one rail and one
evidence panel around them, and shows whichever engine's panel is relevant.

The alternative - porting one UI into the other - would mean re-deriving ~443 KB
of frontend logic covering six analysis modules, which is exactly where
capability gets lost silently.
"""
from __future__ import annotations

import re
from pathlib import Path

_BODY = re.compile(r"<body[^>]*>(.*)</body>", re.DOTALL | re.IGNORECASE)
_BODY_CLASS = re.compile(r"<body[^>]*\bclass=\"([^\"]*)\"", re.IGNORECASE)
_SCRIPT_SRC = re.compile(r"<script[^>]*\bsrc=\"([^\"]+)\"[^>]*>\s*</script>", re.IGNORECASE)
_STYLESHEET = re.compile(r"<link[^>]*\brel=\"stylesheet\"[^>]*>", re.IGNORECASE)

_CAPTURE_STATIC = (
    Path(__file__).resolve().parents[3]
    / "packages"
    / "capture_inspector"
    / "capture_inspector"
    / "static"
)

_SHELL_STATIC = Path(__file__).resolve().parent / "static"


def _asset(name: str) -> str:
    """Shell asset URL stamped with the file's modification time.

    Without this a browser keeps serving a cached stylesheet after an edit, which
    looks exactly like the edit having no effect.
    """
    path = _SHELL_STATIC / name
    stamp = int(path.stat().st_mtime) if path.exists() else 0
    return f"/atlas/{name}?v={stamp}"


def _split_document(html: str) -> tuple[str, str, list[str], str]:
    """Return (body_inner, body_class, external_script_srcs, head_stylesheets)."""
    body_match = _BODY.search(html)
    body = body_match.group(1) if body_match else html
    class_match = _BODY_CLASS.search(html)
    body_class = class_match.group(1) if class_match else ""

    head = html.split("</head>", 1)[0] if "</head>" in html else ""
    stylesheets = "\n".join(_STYLESHEET.findall(head))

    scripts = _SCRIPT_SRC.findall(body)
    # External scripts are re-emitted at the end of the composed document so
    # both engines initialise after all markup exists.
    body = _SCRIPT_SRC.sub("", body)
    return body, body_class, scripts, stylesheets


def capture_document(prefix: str = "/capture") -> str:
    """Capture Inspector's page, with its absolute asset paths prefixed.

    Its markup carries a hand-written ``?v=`` stamp that does not change when
    the file does, so a browser goes on serving a cached ``app.js`` after an
    edit and the edit looks like it had no effect. Restamp with each file's
    modification time, the same rule the shell's own assets follow. The engine
    does this for its standalone page too; the shell composes the document
    itself and so never passes through that code.
    """
    html = (_CAPTURE_STATIC / "index.html").read_text(encoding="utf-8")
    for name in ("app.js", "style.css"):
        asset = _CAPTURE_STATIC / name
        stamp = int(asset.stat().st_mtime) if asset.exists() else 0
        html = re.sub(
            r"(/static/" + re.escape(name) + r")\?v=\d+",
            r"\g<1>?v=" + str(stamp),
            html,
        )
    return html.replace('="/static/', f'="{prefix}/static/')


def bundle_document() -> str:
    """DartHawk's page, produced by its own view function.

    Calling the view rather than rendering the template directly means its
    template context comes from the one place that owns it, so new context
    variables cannot silently break this composition.

    Rendered outside its mount, Flask's url_for emits root-relative asset URLs
    (/static/...), which do not exist at the ATLAS root. They are rewritten to
    the prefix the engine is actually served from.
    """
    import darthawk

    with darthawk.app.test_request_context("/"):
        rendered = darthawk.app.view_functions["index"]()
    html = rendered if isinstance(rendered, str) else rendered.get_data(as_text=True)
    return html.replace('="/static/', '="/bundle/static/')


def compose() -> str:
    """One document containing both engines, wrapped in the ATLAS shell."""
    capture_html = capture_document()
    bundle_html = bundle_document()

    cap_body, _, cap_scripts, cap_css = _split_document(capture_html)
    bun_body, bun_class, bun_scripts, bun_css = _split_document(bundle_html)

    # Each engine keeps its own rules, so both stylesheets are needed. The ATLAS
    # ones appear in both documents and must not be emitted twice.
    shared = ("atlas-tokens.css", "atlas-shell.css", "atlas-workspace.css")
    engine_css = [
        line.strip()
        for line in (cap_css + "\n" + bun_css).split("\n")
        if line.strip() and not any(name in line for name in shared)
    ]
    stylesheets = "\n    ".join(dict.fromkeys(engine_css))
    scripts = "\n    ".join(
        f'<script src="{src}"></script>'
        for src in dict.fromkeys(cap_scripts + bun_scripts)
        if "atlas-shell.js" not in src
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ATLAS - Cisco endpoint and network diagnostics</title>
    <script>
        (function () {{
            try {{
                if (localStorage.getItem('darthawkTheme') === 'darker') {{
                    document.documentElement.classList.add('theme-darker');
                }}
            }} catch (_e) {{ /* storage may be blocked */ }}
        }})();
    </script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = {{ corePlugins: {{ preflight: false }} }};</script>
    <script>
        // The capture engine's API is mounted under a prefix; served standalone
        // its own route injects this. In the composed workspace nothing else
        // does, and without it every call would fall back to the ATLAS root.
        window.API_BASE = "/capture";
    </script>
    <link rel="stylesheet" href="{_asset('atlas-tokens.css')}">
    <link rel="stylesheet" href="{_asset('atlas-shell.css')}">
    {stylesheets}
    <!-- Loaded after the engines so the shell can override their page-level
         chrome. Both were written assuming they own the document. -->
    <link rel="stylesheet" href="{_asset('atlas-workspace.css')}">
</head>
<body class="{bun_class} atlas-workspace">
    <div id="atlas-engine-capture" class="atlas-engine">{cap_body}</div>
    <div id="atlas-engine-bundle" class="atlas-engine">{bun_body}</div>
    {scripts}
    <script src="{_asset('atlas-shell.js')}"></script>
    <script src="{_asset('atlas-workspace.js')}"></script>
</body>
</html>
"""
