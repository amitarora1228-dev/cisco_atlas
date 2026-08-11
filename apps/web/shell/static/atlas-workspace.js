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
            return label && label.offsetParent !== null;
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
        host.innerHTML = "";
        setSummaryMode(true);

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
            host.appendChild(section);
        });

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

    function analyzeEntireBundle() {
        var input = scoped(BUNDLE, "#dartFile");
        if (!input || !input.files || !input.files.length) return;

        var body = new FormData();
        body.append("file", input.files[0]);

        announce("Analysing everything in the bundle. This can take a minute.");
        showEngine(BUNDLE);

        // One upload; the server runs every check in-process. Driving the matrix
        // from here would re-send the archive once per check.
        fetch("/atlas/api/bundle/analyze-all", { method: "POST", body: body })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                renderBundleResults(data.results || [], data.excluded || []);
                clearNotice();
            })
            .catch(function (e) {
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
     * untouched. */
    function wireAnalyze() {
        var run = document.querySelector("#" + CAPTURE + " #run");
        if (!run) return;

        run.addEventListener("click", function (event) {
            var loaded = loadedFiles();

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
                        showEngine(BUNDLE);
                    }
                } else {
                    analyzeEntireBundle();
                }
            }

            // With no capture artifact the capture engine would report a missing
            // file, which is noise when the user only supplied a bundle.
            if (!loaded.capture) {
                event.preventDefault();
                event.stopImmediatePropagation();
            }
        }, true);
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

    /* ---- navigation ------------------------------------------------------ */

    function showEngine(which) {
        [CAPTURE, BUNDLE].forEach(function (id) {
            var node = document.getElementById(id);
            if (node) node.classList.toggle("is-active", id === which);
        });
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
        wireAnalyze();

        var layout = el("div", "atlas-layout");
        layout.appendChild(buildRail());

        var main = el("main", "atlas-main");
        [CAPTURE, BUNDLE].forEach(function (id) {
            var node = document.getElementById(id);
            if (node) main.appendChild(node);
        });
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
