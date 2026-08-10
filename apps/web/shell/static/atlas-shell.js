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

    function init() {
        var active = activeModule();
        if (!active) return;

        var header = buildHeader(active);
        document.body.insertBefore(header, document.body.firstChild);
        adoptControls(header);
        reportHealth(header.querySelector(".atlas-actions"));
        document.body.classList.add("atlas-shell");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
