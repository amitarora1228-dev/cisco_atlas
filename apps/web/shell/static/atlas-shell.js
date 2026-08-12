/* ATLAS shell - one header, one module switcher, across both engines.
 *
 * The guiding constraint is that no control may be lost. Rather than rebuilding
 * each engine's chrome, the shell *relocates* the existing nodes into its
 * header. Moving a DOM node preserves its event listeners, so every button keeps
 * working with no change to either engine's JavaScript.
 *
 * Loaded by both engines. It detects which module it is running inside from the
 * URL prefix, so neither engine has to tell it.
 */
(function () {
    "use strict";

    var MODULES = [
        { id: "capture", label: "Traffic Capture", href: "/capture/", prefix: "/capture" },
        { id: "bundle", label: "Endpoint Bundle", href: "/bundle/", prefix: "/bundle" }
    ];

    // Controls each engine owns that belong in the shared header. Order matters:
    // it is the order they appear in the header. Entries may be an element id or
    // a CSS selector - not every control the engines own has an id, and anything
    // left behind would be hidden along with the chrome it came from.
    var ADOPT = [
        "#tshark-status",        // capture: engine health
        "#readmeToggle",         // bundle: Read Me
        "#feedbackToggle",       // bundle: feedback form
        "#themeToggle",          // bundle: light/darker
        "#help-btn",             // capture: quick help
        ".topbar-icon.avatar"    // capture: user badge, has no id
    ];

    function activeModule() {
        // The unified workspace holds both engines at once, so no single module
        // is active there and the rail, not the header, does the switching.
        if (document.body.classList.contains("atlas-workspace")) return "workspace";
        var path = window.location.pathname;
        for (var i = 0; i < MODULES.length; i++) {
            if (path.indexOf(MODULES[i].prefix) === 0) {
                return MODULES[i].id;
            }
        }
        return null;
    }

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text) node.textContent = text;
        return node;
    }

    function buildHeader(active) {
        var header = el("header", "atlas-header");
        header.setAttribute("role", "banner");

        var brand = el("div", "atlas-brand");
        var logo = document.createElement("img");
        logo.className = "atlas-brand-logo";
        logo.src = "/atlas/cisco-logo.svg";
        logo.alt = "Cisco";
        brand.appendChild(logo);
        brand.appendChild(el("span", "atlas-brand-name", "ATLAS"));
        header.appendChild(brand);

        var nav = el("nav", "atlas-modules");
        nav.setAttribute("aria-label", "Analysis modules");
        if (active !== "workspace") {
            MODULES.forEach(function (mod) {
                var link = document.createElement("a");
                link.className = "atlas-module" + (mod.id === active ? " is-active" : "");
                link.href = mod.href;
                link.appendChild(el("span", null, mod.label));
                if (mod.id === active) link.setAttribute("aria-current", "page");
                nav.appendChild(link);
            });
        }
        header.appendChild(nav);

        header.appendChild(el("div", "atlas-actions"));
        return header;
    }

    function adoptControls(header) {
        var actions = header.querySelector(".atlas-actions");
        ADOPT.forEach(function (selector) {
            var node = document.querySelector(selector);
            // Moving rather than cloning is deliberate: a clone would drop the
            // listeners the owning engine attached.
            if (node) actions.appendChild(node);
        });
        return actions.childElementCount;
    }

    function reportHealth(actions) {
        // Capture Inspector fills its own status pill. In the bundle module that
        // pill does not exist, so the shell reports engine health itself.
        if (document.getElementById("tshark-status")) return;

        var pill = el("span", "pill pill-muted", "checking engine...");
        pill.id = "atlas-health";
        actions.insertBefore(pill, actions.firstChild);

        fetch("/healthz")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var ok = data && data.tshark && data.tshark.available;
                pill.textContent = ok ? "tshark ready" : "tshark missing";
                pill.className = "pill " + (ok ? "pill-ok" : "pill-warn");
                if (!ok) {
                    pill.title = "Packet capture analysis is unavailable. "
                        + "Bundle analysis is unaffected.";
                }
            })
            .catch(function () {
                pill.textContent = "engine status unknown";
            });
    }

    /* Panels belonging to header controls must leave the engine they came from.
     *
     * Read Me, Feedback and the help popover are owned by one engine but reached
     * from the shared header, so they can be opened while a *different* engine
     * is on screen. Their toggles were working the whole time - the class came
     * off correctly - but the panel sits inside an engine panel that is
     * `display:none` unless it is the active one, so it un-hid into nothing and
     * read as a dead button. Three separate reports, one cause.
     *
     * Moving the node is what fixes it, and moving is also what makes it safe:
     * a moved node keeps its listeners, so neither engine's JavaScript changes.
     * The host is inert until something inside it is shown, so it never steals
     * a click from the page underneath.
     */
    var LIFT = ["#readmePanel", "#feedbackPanel", "#help-pop"];

    function liftPanels() {
        var host = document.getElementById("atlas-overlay");
        if (!host) {
            host = el("div", "atlas-overlay");
            host.id = "atlas-overlay";
            document.body.appendChild(host);
        }
        LIFT.forEach(function (selector) {
            var node = document.querySelector(selector);
            if (!node || node.parentElement === host) return;
            host.appendChild(node);
            addCloser(node);
        });
    }

    /* The header button toggles these, so clicking it again closes them - but
     * that is not discoverable once the panel covers what the reader was
     * looking at. The close button drives the engine's own toggle rather than
     * hiding the panel directly, so the engine's idea of open stays true. */
    function addCloser(panel) {
        if (panel.id === "help-pop") return;
        if (panel.querySelector(".atlas-overlay-close")) return;
        var toggle = panel.id === "readmePanel"
            ? document.getElementById("readmeToggle")
            : document.getElementById("feedbackToggle");
        var close = el("button", "atlas-overlay-close", "\u2715");
        close.type = "button";
        close.setAttribute("aria-label", "Close");
        close.addEventListener("click", function () {
            if (toggle) toggle.click();
            else panel.classList.add("hidden");
        });
        panel.insertBefore(close, panel.firstChild);
    }

    function init() {
        var active = activeModule();
        if (!active) return;

        var header = buildHeader(active);
        document.body.insertBefore(header, document.body.firstChild);
        adoptControls(header);
        reportHealth(header.querySelector(".atlas-actions"));
        document.body.classList.add("atlas-shell");
        liftPanels();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
