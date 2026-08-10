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
        host.appendChild(el("h2", "atlas-results-title", "Endpoint bundle - full analysis"));

        var answered = results.filter(function (r) { return r.ok && r.text; });
        host.appendChild(el("p", "atlas-results-sub",
            answered.length + " of " + results.length + " checks returned findings. "
            + "Checks that need a specific destination or identifier are not included; "
            + "select the module in the left panel to run those."));

        results.forEach(function (r) {
            var box = el("details", "atlas-result" + (r.ok ? "" : " is-error"));
            var head = document.createElement("summary");
            head.appendChild(el("span", "atlas-result-name", r.label));
            head.appendChild(el("span", "atlas-result-state",
                r.ok ? (r.text ? "answered" : "nothing found") : (r.error || "not applicable")));
            box.appendChild(head);
            var body = el("pre", "atlas-result-body", r.text || r.error || "");
            box.appendChild(body);
            host.appendChild(box);
        });

        // A skipped check should be a visible choice, not a silent gap.
        (excluded || []).forEach(function (x) {
            var box = el("div", "atlas-result is-skipped");
            var head = el("div", "atlas-result-head");
            head.appendChild(el("span", "atlas-result-name", x.label));
            head.appendChild(el("span", "atlas-result-state", "not run"));
            box.appendChild(head);
            box.appendChild(el("p", "atlas-result-reason", x.reason));
            host.appendChild(box);
        });
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
        bundleBtn.addEventListener("click", function () { showEngine(BUNDLE); });
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
