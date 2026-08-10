"""Ad-hoc check that the workspace composition contains both engines."""
import re

from web.shell.workspace import compose

html = compose()
print("composed document:", len(html), "bytes")
for marker in [
    "atlas-engine-capture",
    "atlas-engine-bundle",
    "dartFile",
    "atlas-workspace.js",
    "uploadForm",
]:
    print(f"  contains {marker:28} {marker in html}")

print("\n=== script srcs ===")
for src in re.findall(r'<script[^>]*src="([^"]+)"', html):
    print("   ", src)

print("=== stylesheet hrefs ===")
for href in re.findall(r'<link[^>]*href="([^"]+)"', html):
    print("   ", href)
