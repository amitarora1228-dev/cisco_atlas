/* ATLAS unified workspace.
 *
 * One tool, not two behind a switcher. The capture engine's "Provide evidence"
 * step is the single entry point for every artifact - packet capture, HAR and
 * DART bundle - and one rail carries every view both engines offer.
 *
 * Nothing is reimplemented. The workspace rearranges what already exists:
 *   - It *moves* the engines' own nodes rather than cloning them, so their event
 *     listeners survive and both engines behave exactly as they do standalone.
 *   - Files are assigned to each engine's own <input type=file>, so that
 *     engine's existing change handler, validation and analysis flow run.
 *
 * This is only safe because the two frontends were measured to be compatible:
 * 0 element-id collisions and 0 top-level JavaScript name collisions.
 */
(function () {
    "use strict";

    var CAPTURE = "atlas-engine-capture";
    var BUNDLE = "atlas-engine-bundle";
    var CORRELATE = "atlas-engine-correlate";

    /* The bundle engine posts to root-relative paths (/analyze, /inspect-bundle,
     * ...) because standalone it owns the origin. Here it is mounted under
     * /bundle, so those calls 404 and the UI reports that it cannot read the
     * file. Rewriting them here avoids editing seven call sites inside a 398 KB
     * file whose behaviour is not covered by tests. */
    var BUNDLE_ROUTES = ["/analyze", "/inspect-bundle", "/agent-chat", "/feedback"];

    function installFetchShim() {
        var original = window.fetch;
        window.fetch = function (input, init) {
            var url = typeof input === "string" ? input : (input && input.url);
            if (typeof url === "string" && BUNDLE_ROUTES.indexOf(url.split("?")[0]) !== -1) {
                var rewritten = "/bundle" + url;
                if (typeof input === "string") {
                    return original.call(this, rewritten, init);
                }
                return original.call(this, new Request(rewritten, input), init);
            }
            return original.apply(this, arguments);
        };
    }

    function el(tag, cls, text) {
        var n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text) n.textContent = text;
        return n;
    }

    function scoped(engine, selector) {
        var root = document.getElementById(engine);
        return root ? root.querySelector(selector) : null;
    }

    /* ---- evidence -------------------------------------------------------- */

    /* Hand a file to an engine's own input so its existing handlers fire. */
    function handOff(input, file) {
        if (!input) return false;
        var dt = new DataTransfer();
        dt.items.add(file);
        input.files = dt.files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
    }

    /* A DART bundle tile matching the capture engine's evidence cards. It is a
     * proxy for the bundle engine's own #dartFile rather than a replacement:
     * that input stays inside its form, where the engine's submit logic needs
     * it. */
    function buildBundleCard() {
        var label = el("label", "drop");
        label.id = "drop-bundle";

        var picker = document.createElement("input");
        picker.type = "file";
        picker.accept = ".zip";
        picker.hidden = true;

        var inner = el("div", "drop-inner");
        var icon = el("span", "drop-icon");
        icon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            + 'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">'
            + '<path d="M4 7a2 2 0 0 1 2-2h4l2 2h6a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/>'
            + '<path d="M12 11v5"/><path d="M9.5 13.5L12 11l2.5 2.5"/></svg>';
        var title = document.createElement("strong");
        title.textContent = "DART bundle";
        var hint = el("span", "hint",
            "Cisco Secure Client diagnostics - ZTA, VPN, Umbrella, UZTNA, EDLP");
        var name = el("span", "filename", "no file selected");
        name.id = "bundle-name";

        inner.appendChild(icon);
        inner.appendChild(title);
        inner.appendChild(hint);
        inner.appendChild(name);
        label.appendChild(picker);
        label.appendChild(inner);

        picker.addEventListener("change", function () {
            var file = picker.files && picker.files[0];
            if (!file) return;
            if (handOff(scoped(BUNDLE, "#dartFile"), file)) {
                name.textContent = file.name;
                label.classList.add("has-file");
            } else {
                name.textContent = "could not be loaded";
            }
        });

        return label;
    }

    /* The key log stays available - it is what decrypts TLS 1.3 and reveals the
     * real certificate inside a CONNECT tunnel - but it is no longer one of the
     * primary artifacts. */
    function demoteKeylog(section) {
        var keylog = document.getElementById("drop-keylog");
        if (!keylog || !section) return;

        var advanced = el("details", "atlas-advanced");
        var summary = document.createElement("summary");
        summary.textContent = "Advanced: TLS key log (decrypts TLS 1.3)";
        advanced.appendChild(summary);
        advanced.appendChild(keylog);

        var helpBtn = document.getElementById("keylog-help-btn");
        if (helpBtn) advanced.appendChild(helpBtn);
        section.appendChild(advanced);
    }

    function rebuildEvidence() {
        var drops = scoped(CAPTURE, ".drops");
        if (!drops) return;
        demoteKeylog(scoped(CAPTURE, "#sec-evidence"));
        drops.appendChild(buildBundleCard());
    }

    /* Say what is actually loaded, not what was last clicked - and let it be
     * taken back.
     *
     * Every filename label here is written by a `change` or `drop` handler and
     * by nothing else, so it describes the last interaction rather than the
     * state of the input. Browsers restore file input selections across a
     * reload - Firefox notably does - which leaves the input holding a capture
     * while the tile reads "no file selected". Analyze then correctly uses the
     * file, and the screen looks like it invented one: a correlation reporting
     * "capture + bundle + har" beside two tiles claiming nothing was chosen.
     *
     * The files are real, so they are not discarded behind the user's back.
     * The labels are corrected to match them, and each tile gains a Remove
     * control - without one there was no way to take a file back at all, which
     * is what made a restored selection feel like the tool inventing data.
     */
    var EVIDENCE_TILES = [
        { input: "#" + CAPTURE + " #pcap", label: "pcap-name", drop: "drop-pcap", size: true },
        { input: "#" + CAPTURE + " #har", label: "har-name", drop: "drop-har", size: true },
        { input: "#" + CAPTURE + " #keylog", label: "keylog-name", drop: "drop-keylog", size: true },
        { input: "#" + BUNDLE + " #dartFile", label: "bundle-name", drop: "drop-bundle", size: false }
    ];

    function refreshEvidenceTiles() {
        EVIDENCE_TILES.forEach(function (tile) {
            var input = document.querySelector(tile.input);
            var label = document.getElementById(tile.label);
            var drop = document.getElementById(tile.drop);
            if (!input || !label || !drop) return;

            var file = input.files && input.files[0];
            var clear = drop.querySelector(".atlas-clear");

            if (!file) {
                label.textContent = "no file selected";
                drop.classList.remove("has-file");
                if (clear) clear.parentNode.removeChild(clear);
                return;
            }

            label.textContent = tile.size
                ? file.name + " (" + (file.size / 1024 / 1024).toFixed(2) + " MB)"
                : file.name;
            drop.classList.add("has-file");

            if (clear) return;
            clear = el("button", "atlas-clear", "Remove");
            clear.type = "button";
            clear.title = "Remove this file";
            // The tile is a <label> wrapping the input, so a plain click here
            // would reopen the file picker instead of clearing it.
            clear.addEventListener("click", function (event) {
                event.preventDefault();
                event.stopPropagation();
                input.value = "";
                refreshEvidenceTiles();
            });
            drop.appendChild(clear);
        });
    }

    function wireEvidenceTiles() {
        EVIDENCE_TILES.forEach(function (tile) {
            var input = document.querySelector(tile.input);
            if (!input) return;
            // A reload starts over.
            //
            // Firefox restores file input selections across a reload, the way
            // it restores text typed into a field. Chromium does not, which is
            // why the browser harness cannot see this. The result was a
            // half-state: the files survived but their results did not, so an
            // apparently empty page would analyse artefacts the reader believed
            // they had never supplied - reported three times, each time as the
            // tool inventing data.
            //
            // Showing the restored files instead of hiding them was the first
            // attempt and was not enough; a reload is the one gesture everyone
            // means as "start again". Selections are therefore dropped at
            // startup. Nothing is lost that a reload was not already discarding,
            // and Remove exists for taking a file back without reloading.
            input.value = "";
            input.addEventListener("change", refreshEvidenceTiles);
        });
        refreshEvidenceTiles();
    }

    /* ---- analysis -------------------------------------------------------- */

    function loadedFiles() {
        var has = function (sel) {
            var n = document.querySelector(sel);
            return !!(n && n.files && n.files.length);
        };
        return {
            capture: has("#" + CAPTURE + " #pcap") || has("#" + CAPTURE + " #har"),
            bundle: has("#" + BUNDLE + " #dartFile")
        };
    }

    /* Is this node one the engine is actually showing?
     *
     * Not answerable with offsetParent here. The workspace hides whichever
     * engine is not on screen, and *nothing* inside a display:none subtree has
     * an offsetParent - so every control in the bundle engine reads as hidden
     * whenever the user is looking at the capture engine, whatever the engine
     * itself intends. Computed style does not have that problem: a descendant
     * of a hidden element still reports its own display value.
     *
     * So walk up to the engine root and ask each ancestor in between, which
     * answers what the engine is showing independently of what the workspace
     * is showing.
     */
    function shownByEngine(node, engine) {
        var root = document.getElementById(engine);
        for (var n = node; n && n !== root; n = n.parentElement) {
            var style = window.getComputedStyle(n);
            if (style.display === "none" || style.visibility === "hidden") return false;
        }
        return true;
    }

    /* True when the chosen module offers check options but none is selected.
     * Detected from the controls actually present, so a module that needs no
     * check is not blocked by a rule hardcoded here. */
    function needsCheckOption() {
        var options = document.querySelectorAll(
            "#" + BUNDLE + " input[name=spa_check_option]"
        );
        if (!options.length) return false;
        var visible = Array.prototype.some.call(options, function (o) {
            var label = document.querySelector('label[for="' + o.id + '"]');
            return label && shownByEngine(label, BUNDLE);
        });
        if (!visible) return false;
        return !document.querySelector(
            "#" + BUNDLE + " input[name=spa_check_option]:checked"
        );
    }

    /* Everything the bundle engine can answer without asking the user for a
     * target value.
     *
     * The engine is query-driven: one module per request, and for ZTA one check
     * as well. "Analyse everything" therefore means running the matrix and
     * collecting the answers, not one clever call.
     *
     * Deliberately excluded: Check SIA Flow, Check TCP or UDP Flow and SRV Check
     * all need a destination or identifier from the user, so they cannot be part
     * of a blanket run. They stay available by selecting the module manually.
     */

    /* The bundle engine's own upload panel is the way *in*; once results exist it
     * is behind them and reads as a second, contradictory page. Collapse the
     * engine while the summary is on screen, and give the user an explicit way
     * back to it. */
    function setSummaryMode(on) {
        var root = document.getElementById(BUNDLE);
        if (root) root.classList.toggle("is-summary", !!on);
        if (!on) returnSnapshot();
    }

    /* The bundle engine already builds a ZTA Health Snapshot from the same
     * upload, and it interprets: verdict, severity, what it means, impact,
     * suggested next steps. Rendering our own verdict beside it produced two
     * answers to one question - on the test bundle the snapshot read "Degraded,
     * review User Pause" while our check list read "no problems reported".
     *
     * The snapshot wins, so it becomes the verdict and our checks move beneath
     * it. The node is *moved*, never rebuilt, so every listener the engine
     * attached to it keeps working, and it is put back where it came from when
     * the user returns to the engine's own page. */
    var snapshotHome = null;

    function adoptSnapshot(host) {
        var snap = document.getElementById("ztaSummaryPanel");
        if (!snap || snap.classList.contains("hidden")) return null;
        if (!snapshotHome) {
            snapshotHome = { parent: snap.parentNode, next: snap.nextSibling };
        }
        host.appendChild(snap);
        return snap;
    }

    function returnSnapshot() {
        var snap = document.getElementById("ztaSummaryPanel");
        if (!snap || !snapshotHome || !snapshotHome.parent) return;
        snapshotHome.parent.insertBefore(snap, snapshotHome.next);
        snapshotHome = null;
    }

    /* Leaving the summary means "I want to drive the engine myself", so the
     * engine's page becomes the whole view - results hidden, not merely pushed
     * down. Leaving them on screen above a fresh form is the stacked-pages
     * problem again: two entry points, one of them stale.
     *
     * The results are hidden, never discarded, and a single bar offers the way
     * back so a completed analysis is not lost by clicking a module. */
    function enterSummary() {
        var host = document.getElementById("atlas-bundle-results");
        if (!host) return;
        setSummaryMode(true);
        var snap = adoptSnapshot(host);
        var all = host.querySelector(".atlas-allchecks");
        if (snap && all) host.insertBefore(snap, all);
        if (host.scrollIntoView) host.scrollIntoView({ block: "start" });
    }

    function resumeBar() {
        var root = document.getElementById(BUNDLE);
        if (!root) return;
        if (document.getElementById("atlas-resume")) return;

        var bar = el("div", "atlas-resume");
        bar.id = "atlas-resume";
        bar.appendChild(el("span", "atlas-resume-text",
            "Full bundle analysis is ready"));
        var back = el("button", "atlas-resume-btn", "Back to summary");
        back.type = "button";
        back.addEventListener("click", enterSummary);
        bar.appendChild(back);
        root.insertBefore(bar, root.firstChild);
    }

    function currentBundleName() {
        var input = scoped(BUNDLE, "#dartFile");
        var file = input && input.files && input.files[0];
        return file ? file.name : "";
    }

    /* The engine answers "No matching logs found." as ordinary text. Counting
     * that as a finding would claim something the bundle does not show. */
    function hasFinding(r) {
        if (!r.ok || !r.text) return false;
        return !/^no matching logs found\.?$/i.test(r.text.trim());
    }

    /* Output means opposite things depending on what the check asked, so the
     * groups are ordered by how much a reader should care, and each says what
     * its own output signifies. The server tags every result with its kind. */
    var GROUPS = [
        {
            kind: "errors",
            title: "Problems reported",
            blurb: "These checks only report failures. Output here means something went wrong.",
            withText: "reported",
            withoutText: "none reported"
        },
        {
            kind: "mixed",
            title: "Status - read these",
            blurb: "These report status and errors together, so they produce output even on "
                + "a healthy client. Output here is not itself a fault; the text has to be read.",
            withText: "reported",
            withoutText: "nothing reported"
        },
        {
            kind: "state",
            title: "Configuration and state",
            blurb: "What the client is set to and the state it was in. Output here is expected, not a fault.",
            withText: "recorded",
            withoutText: "nothing recorded"
        },
        {
            kind: "logs",
            title: "Raw log excerpts",
            blurb: "Log text carried through as-is, for reading rather than for judging.",
            withText: "available",
            withoutText: "empty"
        }
    ];

    function lineCount(text) {
        return text.split("\n").filter(function (l) { return l.trim(); }).length;
    }

    function resultRow(r, group, open) {
        var found = hasFinding(r);
        var box = el("details", "atlas-result"
            + (r.ok ? (found ? " is-answered" : " is-quiet") : " is-error")
            + " is-" + group.kind);
        if (open) box.open = true;

        var summary = document.createElement("summary");
        // The module is already the group's heading; repeating it on every row
        // pushes the distinguishing word out of the scan column.
        summary.appendChild(el("span", "atlas-result-name",
            r.label.replace(/^ZTA - /, "")));

        var meta = el("span", "atlas-result-meta");
        if (found) {
            meta.appendChild(el("span", "atlas-result-lines", lineCount(r.text) + " lines"));
        }
        meta.appendChild(el("span", "atlas-result-state",
            r.ok ? (found ? group.withText : group.withoutText)
                 : (r.error || "not applicable")));
        summary.appendChild(meta);
        box.appendChild(summary);

        box.appendChild(el("pre", "atlas-result-body", r.text || r.error || ""));
        return box;
    }

    function renderBundleResults(results, excluded) {
        var host = document.getElementById("atlas-bundle-results");
        if (!host) {
            host = el("section", "atlas-results");
            host.id = "atlas-bundle-results";
            document.getElementById(BUNDLE).insertBefore(
                host, document.getElementById(BUNDLE).firstChild
            );
        }
        // Put the snapshot back before clearing, or a second run would destroy
        // the engine's node along with our own markup.
        returnSnapshot();
        host.innerHTML = "";
        setSummaryMode(true);
        // Marks that a completed analysis exists to go back to; the resume bar
        // stays hidden until the user leaves the summary.
        document.getElementById(BUNDLE).classList.add("has-results");
        resumeBar();

        var skipped = excluded || [];
        var problems = results.filter(function (r) {
            return r.kind === "errors" && hasFinding(r);
        });

        var head = el("header", "atlas-results-head");
        var heading = el("div", "atlas-results-heading");
        heading.appendChild(el("h2", "atlas-results-title", "Endpoint bundle - full analysis"));
        var name = currentBundleName();
        if (name) heading.appendChild(el("span", "atlas-results-file", name));
        head.appendChild(heading);

        var back = el("button", "atlas-results-back", "Open bundle tool");
        back.type = "button";
        back.addEventListener("click", function () {
            setSummaryMode(false);
            var form = scoped(BUNDLE, "#uploadForm");
            if (form && form.scrollIntoView) form.scrollIntoView({ block: "start" });
        });
        head.appendChild(back);
        host.appendChild(head);

        // The one question worth answering above everything else. It counts only
        // the checks that report failures, so it cannot be inflated by a config
        // dump, and it says which checks - not just how many.
        // The snapshot is the verdict when it exists. Our own banner is the
        // fallback for bundles it cannot speak for - a non-ZTA bundle, or one
        // where the engine returned no signals.
        var snapshot = adoptSnapshot(host);

        if (!snapshot) {
            var verdict = el("div", "atlas-verdict" + (problems.length ? " is-flagged" : " is-clear"));
            if (problems.length) {
                verdict.appendChild(el("strong", "atlas-verdict-title",
                    problems.length === 1
                        ? "1 check reported a problem"
                        : problems.length + " checks reported problems"));
                verdict.appendChild(el("span", "atlas-verdict-detail",
                    problems.map(function (r) { return r.label.replace(/^ZTA - /, ""); }).join(" · ")));
            } else {
                verdict.appendChild(el("strong", "atlas-verdict-title",
                    "No problems reported"));
                verdict.appendChild(el("span", "atlas-verdict-detail",
                    "The checks that report only failures found nothing. That is not proof "
                    + "the endpoint is healthy - the status checks below can still carry "
                    + "errors in their text, and nothing here judges them."));
            }
            host.appendChild(verdict);
        }

        // Every check, folded away. The snapshot covers five of them and reads
        // them better; these are here for the three it does not cover
        // (Inclusions or Exclusions, Duo Desktop, Event Viewer Logs) and for the
        // full text behind all eight. Collapsed, because a reader who needs raw
        // output will go looking for it, and one who does not should not have to
        // scroll past it.
        var answered = results.filter(hasFinding).length;
        var all = el("details", "atlas-allchecks");
        var allSummary = document.createElement("summary");
        allSummary.appendChild(el("span", "atlas-allchecks-title",
            snapshot ? "All checks and full output" : "All checks"));
        allSummary.appendChild(el("span", "atlas-allchecks-count",
            answered + " of " + results.length + " produced output"));
        all.appendChild(allSummary);
        var body = el("div", "atlas-allchecks-body");
        all.appendChild(body);

        GROUPS.forEach(function (group) {
            var mine = results.filter(function (r) { return r.kind === group.kind; });
            if (!mine.length) return;

            var found = mine.filter(hasFinding);
            var rest = mine.filter(function (r) { return !hasFinding(r); });

            var section = el("section", "atlas-group is-" + group.kind);
            var gh = el("header", "atlas-group-head");
            gh.appendChild(el("h3", "atlas-group-title", group.title));
            gh.appendChild(el("span", "atlas-group-count",
                found.length + " of " + mine.length));
            section.appendChild(gh);
            section.appendChild(el("p", "atlas-group-blurb", group.blurb));

            var list = el("div", "atlas-result-list");
            // Within a group, a check with something to say comes first; only a
            // problem is worth opening unasked.
            found.concat(rest).forEach(function (r, i) {
                list.appendChild(resultRow(r, group, group.kind === "errors" && i === 0
                    && hasFinding(r)));
            });
            section.appendChild(list);
            body.appendChild(section);
        });
        host.appendChild(all);

        // A skipped check should be a visible choice, not a silent gap.
        if (skipped.length) {
            var sk = el("section", "atlas-group is-skipped");
            var skh = el("header", "atlas-group-head");
            skh.appendChild(el("h3", "atlas-group-title", "Not run"));
            skh.appendChild(el("span", "atlas-group-count", String(skipped.length)));
            sk.appendChild(skh);
            sk.appendChild(el("p", "atlas-group-blurb",
                "These need a specific destination or identifier. Select the module "
                + "in the left panel to run them."));

            var skl = el("div", "atlas-result-list");
            skipped.forEach(function (x) {
                var box = el("div", "atlas-result is-skipped");
                var row = el("div", "atlas-result-head");
                row.appendChild(el("span", "atlas-result-name", x.label));
                row.appendChild(el("span", "atlas-result-state", "not run"));
                box.appendChild(row);
                box.appendChild(el("p", "atlas-result-reason", x.reason));
                skl.appendChild(box);
            });
            sk.appendChild(skl);
            host.appendChild(sk);
        }
    }

    /* ---- one report for the whole workspace ------------------------------ */

    /* Both engines shipped their own exporter, and under ATLAS neither could
     * see the whole picture: the bundle engine's wrote a header and then
     * "(no detailed output captured)", because it reads its own raw-text pane
     * while the whole-bundle analysis renders into the shell's results block.
     *
     * There is already a Report view, so rather than add a third exporter the
     * shell contributes the sections the capture engine cannot know about and
     * rebinds the existing Download button. Everything is read from the DOM at
     * the moment of export, so the report can never describe a different run
     * than the one on screen.
     */
    var lastCorrelation = null;

    /* Read every word of a rendered block, including the collapsed parts.
     *
     * `innerText` returns what is *rendered*, so text inside a closed
     * `<details>` is omitted. The bundle output is almost entirely inside one -
     * "All checks and full output" - so exporting from the bundle page produced
     * 1,695 characters where the same run exported 387,719 from elsewhere. The
     * earlier measurement was itself misleading: the block was in a hidden
     * subtree at the time, where `innerText` falls back to `textContent` and
     * quietly returns everything.
     *
     * `textContent` would fix the omission but run every block together with no
     * line breaks. So the sections are opened, read, and put back exactly as
     * they were.
     */
    function readableText(node) {
        if (!node) return "";
        var closed = Array.prototype.filter.call(
            node.querySelectorAll("details"),
            function (details) { return !details.open; }
        );
        closed.forEach(function (details) { details.open = true; });
        var text = node.innerText || node.textContent || "";
        closed.forEach(function (details) { details.open = false; });
        return text.trim();
    }

    function reportSections() {
        var sections = [];

        // A <pre> is already preformatted, so its textContent is exactly the
        // report - and it sits inside a collapsed <details> of its own.
        var raw = document.querySelector("#" + CAPTURE + " #report .rp-raw pre");
        if (raw && raw.textContent.trim()) {
            sections.push(["Traffic capture", raw.textContent.trim()]);
        }

        var bundle = readableText(document.getElementById("atlas-bundle-results"));
        if (bundle) {
            sections.push(["Endpoint bundle", bundle]);
        }

        if (lastCorrelation) {
            sections.push(["Across artefacts", correlationReportText(lastCorrelation)]);
        }
        return sections;
    }

    function correlationReportText(data) {
        var lines = [];
        var summary = data.summary || {};
        Object.keys(summary).forEach(function (key) {
            lines.push("  " + key.replace(/_/g, " ") + ": " + summary[key]);
        });
        if (data.clock && data.clock.basis) {
            lines.push("", "Clock offset");
            lines.push("  " + (data.clock.offset_seconds === null
                ? "not measured"
                : "at most " + data.clock.offset_seconds + "s"));
            lines.push("  basis: " + data.clock.basis);
        }

        var flows = data.flows || [];
        if (flows.length) {
            lines.push("", "Intercepted flows, end to end (" + flows.length + ", worst first)");
            flows.forEach(function (flow) {
                lines.push("", "  [" + flow.severity + "] " + flow.destination);
                lines.push("    " + flow.explanation);
                if (flow.wire_basis) lines.push("    wire  : " + flow.wire_basis);
                if (flow.tunnel_basis) lines.push("    tunnel: " + flow.tunnel_basis);
            });
        }

        (data.hosts || []).forEach(function (host, index) {
            if (index === 0) lines.push("", "Hosts");
            lines.push(
                "  " + host.host + " - " + host.steering
                    + " (" + host.requests + " request(s), " + host.failures + " failed)"
            );
            lines.push("    " + host.basis);
        });

        // The refusals are half the value. A report that drops them reads more
        // confident than the evidence behind it.
        (data.notes || []).forEach(function (note, index) {
            if (index === 0) lines.push("", "What these inputs could not answer");
            lines.push("  - " + note);
        });
        return lines.join("\n");
    }

    function buildWorkspaceReport() {
        var files = correlationFiles();
        var rule = new Array(72).join("=");
        var out = [
            "ATLAS - Cisco endpoint and network diagnostics",
            rule,
            "Generated: " + new Date().toISOString(),
            "",
            "Evidence analysed",
        ];
        // A report that does not say what it was made from cannot be checked.
        out.push("  capture: " + (files.capture ? files.capture.name : "not supplied"));
        out.push("  HAR    : " + (files.har ? files.har.name : "not supplied"));
        out.push("  bundle : " + (files.bundle ? files.bundle.name : "not supplied"));

        var sections = reportSections();
        if (!sections.length) {
            out.push("", "No analysis has been run yet, so this report has no content.");
            return out.join("\n");
        }
        sections.forEach(function (pair) {
            out.push("", rule, pair[0].toUpperCase(), rule, "", pair[1]);
        });
        return out.join("\n");
    }

    function downloadReport() {
        var text = buildWorkspaceReport();
        var blob = new Blob([text], { type: "text/plain" });
        var url = URL.createObjectURL(blob);
        var link = document.createElement("a");
        link.href = url;
        link.download = "atlas-report.txt";
        link.click();
        URL.revokeObjectURL(url);
    }

    /* The engines' own export buttons are kept and redirected rather than
     * removed: they are where a user already looks, and both were producing a
     * partial report from the same click. */
    function wireReport() {
        [
            document.querySelector("#" + CAPTURE + " #download"),
            document.getElementById("exportReportBtn")
        ].forEach(function (button) {
            if (!button) return;
            button.addEventListener("click", function (event) {
                event.preventDefault();
                event.stopImmediatePropagation();
                downloadReport();
            }, true);
            button.disabled = false;
        });

        /* Make Report reachable without a capture.
         *
         * The capture engine's views are scroll targets on one long page, and
         * its Report handler sends the reader back to the evidence card unless
         * *it* has results:
         *
         *     if (!resultsReady()) { scrollToEl("sec-evidence"); return; }
         *
         * That was right when the report only described a capture. It is wrong
         * now the report also covers the bundle and the correlation, and it
         * looks like the Report button doing nothing.
         *
         * This listens on the document in the capture phase, which runs before
         * any listener on the button itself, so the engine's handler never
         * runs and there is no race between two smooth scrolls. It only takes
         * over when the engine would have refused and there is genuinely
         * something to read; otherwise the engine keeps its own behaviour.
         */
        document.addEventListener("click", function (event) {
            var nav = event.target && event.target.closest
                ? event.target.closest("#nav-report")
                : null;
            if (!nav) return;
            if (captureHasResults() || !reportSections().length) return;

            event.stopPropagation();
            markActive(nav);
            showEngine(CAPTURE);
            var target = document.getElementById("atlas-report-extra");
            if (!target) return;
            // The engine was hidden a moment ago, so its layout is stale.
            // Reading a layout property forces the reflow synchronously, which
            // is deterministic - waiting for an animation frame is not, since
            // frames are throttled in a background tab. The jump is instant
            // rather than smooth: this is a view switch, and a smooth scroll
            // across a long page is slower to read.
            void target.offsetHeight;
            target.scrollIntoView({ block: "start" });
        }, true);
    }

    function captureHasResults() {
        var results = document.querySelector("#" + CAPTURE + " #results");
        return !!results && !results.classList.contains("hidden");
    }

    /* What is on screen and what is downloaded are built from the same call,
     * so a report can never promise something the Report view did not show.
     *
     * This block deliberately does *not* live inside the engine's own
     * `#sec-report`. That sits inside `#results`, which the engine keeps
     * hidden until it has analysed a capture - so with only a bundle loaded
     * the report was rendered correctly and then displayed at zero height,
     * which looked like the Report button doing nothing.
     */
    function renderReportView() {
        var content = document.querySelector("#" + CAPTURE + " main.content")
            || document.getElementById(CAPTURE);
        if (!content) return;

        var host = document.getElementById("atlas-report-extra");
        if (!host) {
            host = el("div", "atlas-corr-block");
            host.id = "atlas-report-extra";
            content.appendChild(host);
        }
        host.innerHTML = "";

        var all = reportSections();
        var sections = all.filter(function (pair) { return pair[0] !== "Traffic capture"; });
        if (!sections.length) return;

        var hasCaptureReport = all.length !== sections.length;
        host.appendChild(el("h3", null, hasCaptureReport ? "Also in this report" : "Report"));
        host.appendChild(el(
            "p",
            "atlas-corr-blurb",
            (hasCaptureReport
                ? "The capture's own report is above. These sections come from the other artefacts, and "
                : "These sections come from the artefacts analysed so far, and ")
                + "the Download button emits all of them together with a record of which files "
                + "they were made from."
        ));
        sections.forEach(function (pair) {
            var block = el("details", "atlas-report-part");
            block.appendChild(el("summary", null, pair[0]));
            block.appendChild(el("pre", null, pair[1]));
            host.appendChild(block);
        });

        // The engine's own Download button is inside the hidden results
        // section, so with no capture there would be no way to export at all.
        if (!hasCaptureReport && !document.getElementById("atlas-report-download")) {
            var button = el("button", "atlas-corr-run", "Download report (.txt)");
            button.type = "button";
            button.id = "atlas-report-download";
            button.addEventListener("click", downloadReport);
            host.appendChild(button);
        } else if (!hasCaptureReport) {
            host.appendChild(document.getElementById("atlas-report-download"));
        }
    }

    /* Say that work is still happening, and for how long.
     *
     * The notice used to be written once - "This can take a minute" - and then
     * never changed. Both analyses are CPU-bound in one process and serialise,
     * so a capture and a bundle together take two to three minutes where the
     * bundle alone takes about thirty seconds. A static message across that
     * wait is indistinguishable from a hang, and has been reported as one
     * three times. A ticking elapsed time is not progress, and does not claim
     * to be: it only shows the run is alive and names what is still in flight.
     */
    var pendingWork = {};
    var workTimer = null;
    var workStarted = 0;

    function startWork(name) {
        pendingWork[name] = true;
        if (workTimer) return;
        workStarted = Date.now();
        var tick = function () {
            var names = Object.keys(pendingWork);
            if (!names.length) return;
            var seconds = Math.round((Date.now() - workStarted) / 1000);
            var clock = Math.floor(seconds / 60) + ":"
                + ("0" + (seconds % 60)).slice(-2);
            announce(
                "Analysing " + names.join(" and ") + " - " + clock + " elapsed. "
                    + "Analyses share one process, so several together take longer than "
                    + "each would alone."
            );
        };
        tick();
        workTimer = window.setInterval(tick, 1000);
    }

    function endWork(name) {
        delete pendingWork[name];
        if (Object.keys(pendingWork).length) return;
        if (workTimer) window.clearInterval(workTimer);
        workTimer = null;
    }

    function analyzeEntireBundle() {
        var input = scoped(BUNDLE, "#dartFile");
        if (!input || !input.files || !input.files.length) return;

        var body = new FormData();
        body.append("file", input.files[0]);

        announce("Analysing everything in the bundle. This can take a minute.");
        startWork("the bundle");

        // One upload; the server runs every check in-process. Driving the matrix
        // from here would re-send the archive once per check.
        fetch("/atlas/api/bundle/analyze-all", { method: "POST", body: body })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                endWork("the bundle");
                renderBundleResults(data.results || [], data.excluded || []);
                renderReportView();
                // Analyze does not steal the view, because doing so used to hide
                // the capture analysis the same click had started. But when the
                // bundle is the only artefact there is nothing to hide, and
                // leaving the reader on an empty Inspect page while the results
                // sit in a panel they cannot see reads as nothing having
                // happened at all.
                if (!loadedFiles().capture) {
                    showEngine(BUNDLE);
                    clearNotice();
                } else {
                    announce(
                        "Bundle analysis is ready. Open Bundle analysis in the rail to read it."
                    );
                }
            })
            .catch(function (e) {
                endWork("the bundle");
                announce("The bundle could not be analysed: " + e);
            });
    }

    function clearNotice() {
        var note = document.getElementById("atlas-notice");
        if (note) note.classList.remove("is-visible");
    }

    /* One Analyze button for every artifact.
     *
     * Each engine keeps its own analysis flow; this only decides which of them
     * to start. The bundle engine is driven by submitting its form, which is
     * what its own button does, so its validation and request building are
     * untouched.
     *
     * Nothing here changes which view is on screen. It used to jump to the
     * bundle engine, which hid the capture analysis the same click had just
     * started and left the reader looking at an upload panel mid-scan. The
     * results are built into each engine's own panel and stay there, so the
     * rail is the way to them and the notice says so. */
    function wireAnalyze() {
        var run = document.querySelector("#" + CAPTURE + " #run");
        if (!run) return;

        run.addEventListener("click", function (event) {
            var loaded = loadedFiles();
            clearStaleResults();

            if (loaded.bundle) {
                // Analyse whatever the bundle contains, without making the user
                // choose first. A module selected in the rail still narrows it
                // to that engine's own detailed view.
                var chosen = document.querySelector(
                    "#" + BUNDLE + " input[name=module]:checked"
                );
                if (chosen && !needsCheckOption()) {
                    var form = scoped(BUNDLE, "#uploadForm");
                    if (form) {
                        setSummaryMode(false);
                        form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
                        // Same reasoning as the whole-bundle path: only take the
                        // view when there is no capture result to hide behind it.
                        if (!loaded.capture) showEngine(BUNDLE);
                    }
                } else {
                    analyzeEntireBundle();
                }
            }

            maybeCorrelate();

            // With no capture artifact the capture engine would report a missing
            // file, which is noise when the user only supplied a bundle.
            if (!loaded.capture) {
                event.preventDefault();
                event.stopImmediatePropagation();
            }
        }, true);
    }

    /* Correlation is the reason for supplying more than one artefact, so it
     * should not need a second, separate click to happen.
     *
     * Two are enough: the engine states what the missing third could not
     * answer rather than refusing to run. Below two there is nothing to join
     * and a run would only produce notes.
     *
     * The result is deliberately *not* shown here. Correlation finishes on its
     * own schedule, and switching to it would bury whichever engine result the
     * user is reading. The notice points at the rail instead. */
    function maybeCorrelate() {
        var files = correlationFiles();
        var names = [];
        if (files.capture) names.push("capture");
        if (files.har) names.push("HAR");
        if (files.bundle) names.push("bundle");
        if (names.length < 2 || !correlateRun || !correlateStatus) return;
        // Named, not counted. A file input keeps its selection until the page
        // is reloaded, so "3 artefacts" can be true while the user believes
        // they supplied one. Naming them makes that visible instead of
        // puzzling.
        announce(
            "Correlating " + names.join(" + ") + ". Open Correlation in the rail "
                + "for what they say about each other."
        );
        startWork("the correlation");
        runCorrelation(correlateRun, correlateStatus, true);
    }

    /* A run must never be read alongside the one before it.
     *
     * Nothing here used to be cleared, so analysing a bundle after a capture
     * left the capture's findings, its correlation and its notice on screen -
     * output describing artefacts this run did not touch, presented as though
     * it belonged to it. Everything this run will not produce is removed
     * before it starts.
     */
    function clearStaleResults() {
        var files = correlationFiles();
        clearNotice();

        if (!files.capture && !files.har) {
            var results = document.querySelector("#" + CAPTURE + " #results");
            if (results) results.classList.add("hidden");
        }
        if (!files.bundle) {
            var bundle = document.getElementById("atlas-bundle-results");
            if (bundle) bundle.innerHTML = "";
        }

        var supplied = (files.capture ? 1 : 0) + (files.har ? 1 : 0) + (files.bundle ? 1 : 0);
        if (supplied < 2) {
            lastCorrelation = null;
            var corr = document.getElementById("atlas-corr-results");
            if (corr) corr.innerHTML = "";
            if (correlateStatus) correlateStatus.textContent = "";
        }
        renderReportView();
    }

    function announce(message) {
        var note = document.getElementById("atlas-notice");
        if (!note) {
            note = el("div", "atlas-notice");
            note.id = "atlas-notice";
            var section = scoped(CAPTURE, "#sec-evidence");
            if (section) section.appendChild(note);
        }
        note.textContent = message;
        note.classList.add("is-visible");
    }

    /* ---- correlation ----------------------------------------------------- */

    /* Correlation reuses the files already chosen in "Provide evidence" rather
     * than asking for them again. A second set of inputs would let the two
     * drift apart, and a correlation run against different files than the
     * analysis above it would be quietly wrong. */
    function correlationFiles() {
        var pick = function (sel) {
            var n = document.querySelector(sel);
            return n && n.files && n.files.length ? n.files[0] : null;
        };
        return {
            capture: pick("#" + CAPTURE + " #pcap"),
            har: pick("#" + CAPTURE + " #har"),
            bundle: pick("#" + BUNDLE + " #dartFile")
        };
    }

    var STEERING = {
        steered: {
            label: "Steered",
            hint: "The agent intercepted this locally and carried it over the tunnel."
        },
        direct: {
            label: "Direct",
            hint: "This reached the peer without passing through the agent."
        },
        unknown: {
            label: "Not determined",
            hint: "The capture holds no handshake naming this host."
        }
    };

    function correlateSummary(data) {
        var strip = el("div", "atlas-corr-summary");
        var counts = [
            ["Intercepted flows", data.summary.intercepted_flows],
            ["Flows that failed", data.summary.failing_flows],
            ["Hosts", data.summary.hosts],
            ["Steered", data.summary.steered],
            ["Direct", data.summary.direct],
            ["Not determined", data.summary.unknown],
            ["Tunnels matched", data.summary.tunnels],
            ["Requests", data.summary.requests],
            ["Failed requests", data.summary.failures]
        ];
        counts.forEach(function (pair) {
            if (pair[1] === undefined || pair[1] === null) return;
            var cell = el("div", "atlas-corr-stat");
            cell.appendChild(el("span", "atlas-corr-stat-value", String(pair[1])));
            cell.appendChild(el("span", "atlas-corr-stat-label", pair[0]));
            if (pair[1] > 0 && (pair[0] === "Failed requests" || pair[0] === "Flows that failed")) {
                cell.classList.add("is-warning");
            }
            strip.appendChild(cell);
        });
        return strip;
    }

    /* The offset is a measurement with a stated basis, not a correction that
     * has been applied. Showing the basis is the point: an offset derived from
     * one connection deserves less trust than one derived from twenty, and the
     * reader can only weigh that if the basis travels with the number. */
    function correlateClock(data) {
        if (!data.clock || !data.clock.basis) return null;
        var box = el("div", "atlas-corr-clock");
        var value = data.clock.offset_seconds;
        box.appendChild(el(
            "strong",
            null,
            value === null || value === undefined
                ? "Clock offset not measured"
                : "Clock offset at most " + value.toFixed(3) + "s"
        ));
        box.appendChild(el("span", null, data.clock.basis));
        return box;
    }

    function correlateHosts(data) {
        var section = el("section", "atlas-corr-block");
        section.appendChild(el("h3", null, "What happened to each host"));
        section.appendChild(el(
            "p",
            "atlas-corr-blurb",
            "Steering is read from the wire: a TLS handshake to the agent's local "
                + "listener means it was steered, one straight to the peer means it "
                + "was not. The browser's own record supplies the requests and status "
                + "codes."
        ));

        if (!data.hosts.length) {
            section.appendChild(el("p", "atlas-corr-empty", "No hosts were identified."));
            return section;
        }

        var table = el("table", "atlas-corr-table");
        var head = el("tr");
        ["Host", "Steering", "Requests", "Failed", "Evidence"].forEach(function (name) {
            head.appendChild(el("th", null, name));
        });
        table.appendChild(el("thead")).appendChild(head);

        var body = el("tbody");
        data.hosts.forEach(function (host) {
            var meta = STEERING[host.steering] || STEERING.unknown;
            var row = el("tr");
            row.appendChild(el("td", "atlas-corr-host", host.host));

            var badgeCell = el("td");
            var badge = el("span", "atlas-corr-badge is-" + host.steering, meta.label);
            badge.title = meta.hint;
            badgeCell.appendChild(badge);
            row.appendChild(badgeCell);

            row.appendChild(el("td", "atlas-corr-num", String(host.requests)));
            var failed = el("td", "atlas-corr-num", String(host.failures));
            if (host.failures) failed.classList.add("is-warning");
            row.appendChild(failed);

            var evidence = el("td", "atlas-corr-basis");
            evidence.appendChild(el("span", null, host.basis));
            var codes = Object.keys(host.statuses || {});
            if (codes.length) {
                evidence.appendChild(el(
                    "span",
                    "atlas-corr-sub",
                    "Status codes: " + codes.map(function (c) {
                        return c + " x" + host.statuses[c];
                    }).join(", ")
                ));
            }
            row.appendChild(evidence);
            body.appendChild(row);
        });
        table.appendChild(body);
        section.appendChild(table);
        return section;
    }

    function correlateTunnels(data) {
        var section = el("section", "atlas-corr-block");
        section.appendChild(el("h3", null, "Tunnels the agent and the capture both saw"));
        section.appendChild(el(
            "p",
            "atlas-corr-blurb",
            "Matched on connection identity - source port and destination - so these "
                + "are the same connection in both records, with no reliance on either "
                + "clock. Many hosts share one tunnel, so a request cannot be "
                + "attributed to a particular tunnel here."
        ));

        if (!data.tunnels.length) {
            section.appendChild(el(
                "p",
                "atlas-corr-empty",
                "No connection appeared in both the capture and the agent's log."
            ));
            return section;
        }

        data.tunnels.forEach(function (tunnel) {
            var card = el("div", "atlas-corr-tunnel");
            var head = el("div", "atlas-corr-tunnel-head");
            head.appendChild(el("code", null, tunnel.label));
            head.appendChild(el(
                "span",
                "atlas-corr-sub",
                tunnel.packets + " packets, " + tunnel.agent_lines + " agent log line(s)"
                    + (tunnel.handshake_captured ? "" : " - already open when the capture began")
            ));
            card.appendChild(head);

            (tunnel.errors || []).forEach(function (line) {
                var row = el("div", "atlas-corr-event is-error");
                row.appendChild(el("span", "atlas-corr-event-tag", "Error"));
                row.appendChild(el("span", null, line));
                card.appendChild(row);
            });
            (tunnel.warnings || []).forEach(function (line) {
                var row = el("div", "atlas-corr-event is-warning");
                row.appendChild(el("span", "atlas-corr-event-tag", "Warning"));
                row.appendChild(el("span", null, line));
                card.appendChild(row);
            });
            section.appendChild(card);
        });
        return section;
    }

    function correlateNotes(data) {
        if (!data.notes || !data.notes.length) return null;
        var box = el("section", "atlas-corr-block atlas-corr-notes");
        box.appendChild(el("h3", null, "What these inputs could not answer"));
        var list = el("ul");
        data.notes.forEach(function (note) {
            list.appendChild(el("li", null, note));
        });
        box.appendChild(list);
        return box;
    }

    /* The flow list: one intercepted connection, followed across every
     * artefact that saw it.
     *
     * Presented as the capture engine presents its own flows - the same table,
     * the same severity pills, the same expand-for-detail - and reusing that
     * engine's classes rather than inventing a second style for the same idea.
     * A reader who has learned one table has learned both.
     */
    var FLOW_SEVERITY = {
        problem: { pill: "high", label: "high" },
        warning: { pill: "medium", label: "medium" },
        info: { pill: "ok", label: "OK" }
    };

    var flowOnlyProblems = false;
    var flowFilterText = "";

    function esc(value) {
        return String(value === null || value === undefined ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function flowTime(iso) {
        if (!iso) return "—";
        var match = /T(\d{2}:\d{2}:\d{2})/.exec(iso);
        return match ? match[1] : iso;
    }

    function correlateFlows(data) {
        var flows = data.flows || [];
        var section = el("section", "atlas-corr-block");

        var head = el("div", "flows-head");
        head.appendChild(el("h3", null, "Intercepted flows, end to end"));
        var filters = el("div", "filters");
        var label = el("label", "switch");
        var toggle = document.createElement("input");
        toggle.type = "checkbox";
        toggle.checked = flowOnlyProblems;
        label.appendChild(toggle);
        label.appendChild(el("span", null, "Show only problems"));
        var search = document.createElement("input");
        search.className = "flow-filter";
        search.placeholder = "filter by destination…";
        search.value = flowFilterText;
        filters.appendChild(label);
        filters.appendChild(search);
        head.appendChild(filters);
        section.appendChild(head);

        section.appendChild(el(
            "p",
            "atlas-corr-blurb",
            "ZTA steers on rules written against hosts and addresses, so where a rule "
                + "matched, the bundle names the destination the application asked for and the "
                + "source port it used. That name is what the browser recorded, and that port is "
                + "what the capture saw - which is how one flow is followed through all three. "
                + "Open a row for the whole chain and the evidence behind it."
        ));

        if (!flows.length) {
            section.appendChild(el(
                "p",
                "atlas-corr-empty",
                "No intercepted flow was named. Either no DART bundle was supplied, or its Zero "
                    + "Trust Access log named no destination."
            ));
            return section;
        }

        var wrap = el("div", "table-wrap");
        var table = el("table", "ftable");
        table.innerHTML = "<thead><tr>"
            + "<th></th><th>Time</th><th>Severity</th><th>Source</th>"
            + "<th>Destination asked for</th><th>Carried by</th><th>Protocol</th>"
            + "<th>On the wire</th><th>Error / Issue</th>"
            + "</tr></thead>";
        var body = document.createElement("tbody");
        table.appendChild(body);
        wrap.appendChild(table);
        section.appendChild(wrap);

        var empty = el("p", "atlas-corr-empty", "");
        section.appendChild(empty);

        var draw = function () {
            renderFlowRows(body, empty, flows);
        };
        toggle.addEventListener("change", function () {
            flowOnlyProblems = toggle.checked;
            draw();
        });
        search.addEventListener("input", function () {
            flowFilterText = search.value.trim().toLowerCase();
            draw();
        });
        draw();
        return section;
    }

    function renderFlowRows(body, empty, flows) {
        body.innerHTML = "";
        var rows = flows.filter(function (flow) {
            if (flowOnlyProblems && flow.severity === "info") return false;
            if (!flowFilterText) return true;
            return String(flow.destination).toLowerCase().indexOf(flowFilterText) !== -1;
        });

        if (!rows.length) {
            empty.textContent = flowOnlyProblems
                ? "No flow with a fault matches. Turn off \"Show only problems\" to see the rest."
                : "No flow matches that filter.";
            empty.classList.remove("hidden");
            return;
        }
        empty.textContent = rows.length + " of " + flows.length + " flow(s), worst first.";
        empty.classList.remove("hidden");

        var fragment = document.createDocumentFragment();
        rows.slice(0, 200).forEach(function (flow) {
            var tone = FLOW_SEVERITY[flow.severity] || FLOW_SEVERITY.info;
            var row = document.createElement("tr");
            row.className = "row sev-" + tone.pill;

            var problem = flow.reasons.length
                ? flow.reasons.join(", ")
                : (flow.failures
                    ? flow.failures + " failed request(s)"
                    : (flow.error_lines ? flow.error_lines + " error line(s)" : "—"));

            row.innerHTML = "<td><span class=\"caret\">&#9654;</span></td>"
                + "<td class=\"time-cell mono\">" + esc(flowTime(flow.first_seen)) + "</td>"
                + "<td><span class=\"sev-pill sp-" + tone.pill + "\">" + esc(tone.label) + "</span></td>"
                + "<td class=\"mono\">port " + esc(flow.src_port) + "</td>"
                + "<td class=\"sni-cell\">" + esc(flow.destination)
                + (flow.requests ? " <span class=\"badge badge-har\">HAR</span>" : "") + "</td>"
                + "<td class=\"mono\">" + (flow.tunnel
                    ? esc(flow.tunnel) : "<span class=\"muted\">not identified</span>") + "</td>"
                + "<td>" + esc(flow.protocol)
                + (flow.stream === null || flow.stream === undefined
                    ? "" : " <span class=\"muted\">stream " + esc(flow.stream) + "</span>") + "</td>"
                + "<td class=\"mono\">" + (flow.wire
                    ? esc(flow.wire.packets) + " pkt"
                    : "<span class=\"muted\">not captured</span>") + "</td>"
                + "<td class=\"" + (flow.severity === "info" ? "err-cell okish" : "err-cell")
                + "\">" + esc(problem) + "</td>";

            var detail = document.createElement("tr");
            detail.className = "detail-row hidden";
            var built = false;
            row.addEventListener("click", function () {
                if (!built) {
                    detail.innerHTML = "<td colspan=\"9\">" + flowDetailHtml(flow) + "</td>";
                    built = true;
                }
                row.classList.toggle("open");
                detail.classList.toggle("hidden");
            });

            fragment.appendChild(row);
            fragment.appendChild(detail);
        });
        body.appendChild(fragment);
        if (rows.length > 200) {
            empty.textContent = "Showing the first 200 of " + rows.length + " flow(s), worst first.";
        }
    }

    /* The chain, one hop per artefact, each labelled with where it came from.
     * A hop with no evidence says so rather than being omitted - a gap the
     * reader cannot see is a gap they will assume was filled. */
    function flowDetailHtml(flow) {
        var hops = [
            ["Browser", "har", flow.requests
                ? flow.requests + " request(s)"
                    + (flow.failures ? ", " + flow.failures + " failed" : "")
                : "not in the HAR"],
            ["Agent", "bundle", flow.label
                + (flow.stream === null || flow.stream === undefined ? "" : " · stream " + flow.stream)],
            ["Wire", "capture", flow.wire
                ? flow.wire.label + " · " + flow.wire.packets + " packet(s)"
                : "not in the capture"],
            ["Tunnel", "bundle", flow.tunnel || "not identified"]
        ];

        var html = "<p class=\"atlas-flow-why\">" + esc(flow.explanation) + "</p>";
        html += "<div class=\"atlas-flow-chain\">";
        hops.forEach(function (hop) {
            html += "<div class=\"atlas-flow-hop" + (/^not /.test(hop[2]) ? " is-missing" : "") + "\">"
                + "<span class=\"atlas-flow-hop-title\">" + esc(hop[0]) + "</span>"
                + "<span class=\"atlas-flow-hop-value\">" + esc(hop[2]) + "</span>"
                + "<span class=\"atlas-flow-hop-src\">" + esc(hop[1]) + "</span></div>";
        });
        html += "</div>";

        html += "<div class=\"atlas-flow-basis\">";
        [flow.wire_basis, flow.tunnel_basis].forEach(function (text) {
            if (text) html += "<p>" + esc(text) + "</p>";
        });
        html += "</div>";

        var statuses = Object.keys(flow.statuses || {});
        if (statuses.length) {
            html += "<div class=\"atlas-flow-basis\"><p>The browser recorded: "
                + statuses.map(function (code) {
                    return esc(flow.statuses[code]) + " x " + esc(code);
                }).join(", ") + ".</p></div>";
        }

        (flow.agent_errors || []).slice(0, 4).forEach(function (line) {
            html += "<div class=\"atlas-corr-event is-error\">"
                + "<span class=\"atlas-corr-event-tag\">agent</span><span>" + esc(line) + "</span></div>";
        });
        return html;
    }

    function renderCorrelation(data) {
        var host = document.getElementById("atlas-corr-results");
        if (!host) return;
        host.innerHTML = "";
        host.appendChild(correlateSummary(data));
        var clock = correlateClock(data);
        if (clock) host.appendChild(clock);
        host.appendChild(correlateFlows(data));
        host.appendChild(correlateHosts(data));
        host.appendChild(correlateTunnels(data));
        var notes = correlateNotes(data);
        if (notes) host.appendChild(notes);
    }

    var correlateRun = null;
    var correlateStatus = null;

    function runCorrelation(button, status, notify) {
        var files = correlationFiles();
        if (!files.capture && !files.har && !files.bundle) {
            status.textContent = "Add a capture, a HAR or a DART bundle in Provide evidence first.";
            return;
        }

        var form = new FormData();
        if (files.capture) form.append("capture", files.capture);
        if (files.har) form.append("har", files.har);
        if (files.bundle) form.append("bundle", files.bundle);

        button.disabled = true;
        status.textContent = "Correlating...";

        fetch("/atlas/api/correlate", { method: "POST", body: form })
            .then(function (response) {
                return response.json().then(function (data) {
                    if (!response.ok) throw new Error(data.error || "Correlation failed.");
                    return data;
                });
            })
            .then(function (data) {
                var supplied = Object.keys(data.sources || {});
                if (notify) endWork("the correlation");
                status.textContent = "Correlated " + (supplied.length || 0)
                    + " artefact(s): " + (supplied.join(", ") || "none");
                lastCorrelation = data;
                renderCorrelation(data);
                renderReportView();
                // Said again on completion because the bundle engine clears the
                // notice when its own results land, and a pointer the reader
                // never saw is the same as no pointer.
                if (notify) {
                    announce(
                        "Correlation is ready: " + (data.summary ? data.summary.hosts : 0)
                            + " host(s) from " + (supplied.join(" + ") || "no artefact")
                            + ". Open Correlation in the rail."
                    );
                }
            })
            .catch(function (err) {
                if (notify) endWork("the correlation");
                status.textContent = err.message || "Correlation failed.";
                if (notify) announce("Correlation failed: " + (err.message || "unknown error"));
            })
            .then(function () {
                button.disabled = false;
            });
    }

    function buildCorrelateView() {
        var view = el("div", "atlas-engine atlas-corr");
        view.id = CORRELATE;

        var head = el("header", "atlas-corr-head");
        head.appendChild(el("h2", null, "Correlation"));
        head.appendChild(el(
            "p",
            null,
            "Each artefact holds a different half of the same session. The browser "
                + "knows hostnames and status codes but records a synthetic address "
                + "when traffic is steered; the capture sees both the local leg and "
                + "the encrypted tunnel but no hostnames on the tunnel; the bundle "
                + "knows what the agent believed it was doing. Joined, they answer "
                + "what none of them can answer alone."
        ));
        view.appendChild(head);

        var bar = el("div", "atlas-corr-bar");
        var button = el("button", "atlas-corr-run", "Correlate the evidence");
        button.type = "button";
        var status = el("span", "atlas-corr-status");
        status.setAttribute("role", "status");
        button.addEventListener("click", function () { runCorrelation(button, status); });
        correlateRun = button;
        correlateStatus = status;
        bar.appendChild(button);
        bar.appendChild(status);
        view.appendChild(bar);

        var results = el("div", null);
        results.id = "atlas-corr-results";
        view.appendChild(results);
        return view;
    }

    /* ---- navigation ------------------------------------------------------ */

    function showEngine(which) {
        [CAPTURE, BUNDLE, CORRELATE].forEach(function (id) {
            var node = document.getElementById(id);
            if (node) node.classList.toggle("is-active", id === which);
        });
        syncRail(which);
    }

    /* The rail read "Inspect" while the bundle panel filled the screen, because
     * this function moved the panel and nothing moved the highlight. Whoever
     * changes the panel now changes the rail with it.
     *
     * An item already pointing at this engine is left alone: the capture engine
     * has seven views of its own, and re-selecting the first of them would
     * throw the reader back to Inspect every time. */
    function syncRail(which) {
        var active = document.querySelector(".atlas-rail .atlas-rail-item.is-active");
        if (active && active.dataset.engine === which) return;
        var target = document.querySelector(
            '.atlas-rail .atlas-rail-item[data-engine="' + which + '"]'
        );
        if (target) markActive(target);
    }

    function markActive(item) {
        Array.prototype.forEach.call(
            document.querySelectorAll(".atlas-rail .atlas-rail-item"),
            function (n) { n.classList.remove("is-active"); }
        );
        item.classList.add("is-active");
    }

    function buildRail() {
        var rail = el("nav", "atlas-rail");
        rail.setAttribute("aria-label", "Workspace");

        rail.appendChild(el("div", "atlas-rail-title", "Traffic capture"));
        var captureNav = scoped(CAPTURE, ".sidebar");
        if (captureNav) {
            // Moved, not rebuilt: each item keeps the handler that drives the
            // capture engine's own view switching.
            Array.prototype.slice.call(captureNav.querySelectorAll(".nav-item")).forEach(
                function (item) {
                    item.classList.add("atlas-rail-item");
                    item.dataset.engine = CAPTURE;
                    item.addEventListener("click", function () { showEngine(CAPTURE); });
                    rail.appendChild(item);
                }
            );
        }

        rail.appendChild(el("div", "atlas-rail-title", "Endpoint bundle"));
        var bundleBtn = el("button", "atlas-rail-item");
        bundleBtn.type = "button";
        // Icon first so this entry sits on the same optical column as the
        // capture views, which all carry one.
        var bundleIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        bundleIcon.setAttribute("viewBox", "0 0 24 24");
        bundleIcon.setAttribute("fill", "none");
        bundleIcon.setAttribute("stroke", "currentColor");
        bundleIcon.setAttribute("stroke-width", "1.6");
        bundleIcon.setAttribute("stroke-linecap", "round");
        bundleIcon.setAttribute("stroke-linejoin", "round");
        bundleIcon.innerHTML = '<path d="M21 8v8a2 2 0 0 1-1 1.73l-7 4a2 2 0 0 1-2 0l-7-4A2 2 0 0 1 3 16V8a2 2 0 0 1 1-1.73l7-4a2 2 0 0 1 2 0l7 4A2 2 0 0 1 21 8z"/>'
            + '<path d="M3.3 7L12 12l8.7-5"/><path d="M12 22V12"/>';
        bundleBtn.appendChild(bundleIcon);
        bundleBtn.appendChild(el("span", null, "Bundle analysis"));
        bundleBtn.dataset.engine = BUNDLE;
        bundleBtn.addEventListener("click", function () {
            setSummaryMode(false);
            showEngine(BUNDLE);
        });
        rail.appendChild(bundleBtn);

        // The module choice (ZTA, VPN, Umbrella, UZTNA, EDLP) lives inside the
        // bundle engine's <form>, and its radios must stay there or their value
        // is never submitted. So the rail gets proxies that drive the real
        // controls, exactly as the DART evidence tile does for the file input.
        var realModules = scoped(BUNDLE, "#moduleSelectionWrap");
        if (realModules) {
            Array.prototype.slice.call(
                realModules.querySelectorAll("input[name=module]")
            ).forEach(function (radio) {
                var source = realModules.querySelector('label[for="' + radio.id + '"]');
                var item = el("button", "atlas-rail-item atlas-module-item",
                    (source ? source.textContent : radio.value).trim());
                item.type = "button";
                item.dataset.module = radio.value;
                item.dataset.engine = BUNDLE;
                item.addEventListener("click", function () {
                    radio.checked = true;
                    radio.dispatchEvent(new Event("change", { bubbles: true }));
                    setSummaryMode(false);
                    showEngine(BUNDLE);
                    syncModuleSelection();
                });
                rail.appendChild(item);
            });
            realModules.addEventListener("change", syncModuleSelection);
        }

        // Correlation is neither engine's view: it consumes the output of both,
        // so it sits in its own section rather than under either heading.
        rail.appendChild(el("div", "atlas-rail-title", "Across artefacts"));
        var corrBtn = el("button", "atlas-rail-item");
        corrBtn.type = "button";
        var corrIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        corrIcon.setAttribute("viewBox", "0 0 24 24");
        corrIcon.setAttribute("fill", "none");
        corrIcon.setAttribute("stroke", "currentColor");
        corrIcon.setAttribute("stroke-width", "1.6");
        corrIcon.setAttribute("stroke-linecap", "round");
        corrIcon.innerHTML = '<circle cx="8" cy="12" r="5"/><circle cx="16" cy="12" r="5"/>';
        corrBtn.appendChild(corrIcon);
        corrBtn.appendChild(el("span", null, "Correlation"));
        corrBtn.dataset.engine = CORRELATE;
        corrBtn.addEventListener("click", function () {
            setSummaryMode(false);
            showEngine(CORRELATE);
        });
        rail.appendChild(corrBtn);

        rail.addEventListener("click", function (e) {
            var item = e.target.closest(".atlas-rail-item");
            if (item) markActive(item);
        });
        return rail;
    }

    /* Keep the rail proxies showing whichever module the form actually holds. */
    function syncModuleSelection() {
        var checked = document.querySelector(
            "#" + BUNDLE + " input[name=module]:checked"
        );
        Array.prototype.forEach.call(
            document.querySelectorAll(".atlas-module-item"),
            function (item) {
                item.classList.toggle(
                    "is-selected", !!checked && item.dataset.module === checked.value
                );
            }
        );
    }

    /* ---------------------------------------------------------------------- */

    function init() {
        installFetchShim();
        rebuildEvidence();
        wireEvidenceTiles();
        wireAnalyze();
        wireReport();

        var layout = el("div", "atlas-layout");
        layout.appendChild(buildRail());

        var main = el("main", "atlas-main");
        [CAPTURE, BUNDLE].forEach(function (id) {
            var node = document.getElementById(id);
            if (node) main.appendChild(node);
        });
        main.appendChild(buildCorrelateView());
        layout.appendChild(main);
        document.body.appendChild(layout);

        showEngine(CAPTURE);
        var first = document.querySelector(".atlas-rail .atlas-rail-item");
        if (first) markActive(first);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
