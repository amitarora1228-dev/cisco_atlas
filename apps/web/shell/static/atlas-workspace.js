/* ATLAS unified workspace.
 *
 * One page, one evidence panel, both engines. A single investigation normally
 * spans a DART bundle, a packet capture and sometimes a HAR; this keeps them in
 * one session instead of one tool each.
 *
 * The engines are not rewritten. Their markup and scripts are already loaded in
 * this document - which works because they have no element-id or global-name
 * collisions - and this file only:
 *   1. builds the shared header and rail,
 *   2. accepts every artifact type in one drop zone and hands each file to the
 *      engine that understands it, by assigning it to that engine's own input,
 *   3. shows the panel matching the selected view.
 *
 * Handing files to the engines' own <input type=file> elements matters: it means
 * each engine's existing change handlers, validation and analysis flow run
 * unmodified. Nothing is reimplemented here that an engine already does.
 */
(function () {
    "use strict";

    var ENGINES = {
        capture: { root: "atlas-engine-capture", label: "Traffic Capture" },
        bundle: { root: "atlas-engine-bundle", label: "Endpoint Bundle" }
    };

    // Which engine input each artifact belongs to, chosen by file extension.
    var ARTIFACTS = [
        { id: "pcap", label: "Packet capture", exts: [".pcap", ".pcapng", ".cap"],
          engine: "capture", input: "#pcap-input, input[type=file][accept*='pcap']" },
        { id: "har", label: "HAR log", exts: [".har"],
          engine: "capture", input: "input[type=file][accept*='har']" },
        { id: "keylog", label: "TLS key log", exts: [".log", ".keys", ".txt"],
          engine: "capture", input: "input[type=file][accept*='log'], input[type=file][accept*='.keys']" },
        { id: "bundle", label: "DART bundle", exts: [".zip"],
          engine: "bundle", input: "#dartFile" }
    ];

    var state = { loaded: {}, view: null };

    function el(tag, cls, text) {
        var n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text) n.textContent = text;
        return n;
    }

    function artifactFor(file) {
        var name = (file.name || "").toLowerCase();
        for (var i = 0; i < ARTIFACTS.length; i++) {
            var a = ARTIFACTS[i];
            for (var j = 0; j < a.exts.length; j++) {
                if (name.endsWith(a.exts[j])) return a;
            }
        }
        return null;
    }

    /* Give the file to the engine's own input so its existing handlers fire. */
    function handOff(artifact, file) {
        var scope = document.getElementById(ENGINES[artifact.engine].root);
        var input = scope ? scope.querySelector(artifact.input) : null;
        if (!input) return false;

        var dt = new DataTransfer();
        dt.items.add(file);
        input.files = dt.files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
    }

    function acceptFiles(files) {
        Array.prototype.forEach.call(files, function (file) {
            var artifact = artifactFor(file);
            if (!artifact) {
                state.loaded["_rejected_" + file.name] = {
                    label: file.name, detail: "unsupported file type", ok: false
                };
            } else if (handOff(artifact, file)) {
                state.loaded[artifact.id] = { label: artifact.label, detail: file.name, ok: true };
            } else {
                state.loaded[artifact.id] = {
                    label: artifact.label, detail: "could not be loaded", ok: false
                };
            }
        });
        renderEvidence();
    }

    function renderEvidence() {
        var list = document.getElementById("atlas-evidence-list");
        if (!list) return;
        list.innerHTML = "";
        var keys = Object.keys(state.loaded);
        if (!keys.length) {
            list.appendChild(el("p", "atlas-evidence-empty",
                "No evidence loaded yet. Drop a DART bundle, packet capture or HAR above."));
            return;
        }
        keys.forEach(function (k) {
            var item = state.loaded[k];
            var row = el("div", "atlas-evidence-item" + (item.ok ? "" : " is-bad"));
            row.appendChild(el("span", "atlas-evidence-label", item.label));
            row.appendChild(el("span", "atlas-evidence-detail", item.detail));
            list.appendChild(row);
        });
    }

    function buildEvidencePanel() {
        var panel = el("section", "atlas-evidence");
        panel.id = "atlas-evidence";

        var drop = el("div", "atlas-dropzone");
        drop.id = "atlas-dropzone";
        drop.appendChild(el("div", "atlas-dropzone-title", "Drop evidence here"));
        drop.appendChild(el("div", "atlas-dropzone-hint",
            "DART bundle (.zip) - packet capture (.pcap, .pcapng) - HAR log (.har) - TLS key log"));

        var pick = el("button", "atlas-dropzone-btn", "Choose files");
        pick.type = "button";
        var picker = document.createElement("input");
        picker.type = "file";
        picker.multiple = true;
        picker.className = "atlas-hidden-input";
        pick.addEventListener("click", function () { picker.click(); });
        picker.addEventListener("change", function () { acceptFiles(picker.files); });
        drop.appendChild(pick);
        drop.appendChild(picker);

        ["dragenter", "dragover"].forEach(function (evt) {
            drop.addEventListener(evt, function (e) {
                e.preventDefault();
                drop.classList.add("is-over");
            });
        });
        ["dragleave", "drop"].forEach(function (evt) {
            drop.addEventListener(evt, function (e) {
                e.preventDefault();
                drop.classList.remove("is-over");
            });
        });
        drop.addEventListener("drop", function (e) {
            if (e.dataTransfer && e.dataTransfer.files) acceptFiles(e.dataTransfer.files);
        });

        panel.appendChild(drop);
        var list = el("div", "atlas-evidence-list");
        list.id = "atlas-evidence-list";
        panel.appendChild(list);
        return panel;
    }

    function showView(view) {
        state.view = view;
        Object.keys(ENGINES).forEach(function (id) {
            var node = document.getElementById(ENGINES[id].root);
            if (node) node.classList.toggle("is-active", id === view);
        });
        var evidence = document.getElementById("atlas-evidence");
        if (evidence) evidence.classList.toggle("is-hidden", view !== "evidence");
        Array.prototype.forEach.call(
            document.querySelectorAll(".atlas-rail-item"),
            function (b) { b.classList.toggle("is-active", b.dataset.view === view); }
        );
    }

    function buildRail() {
        var rail = el("nav", "atlas-rail");
        rail.setAttribute("aria-label", "Workspace");

        var groups = [
            { title: "Workspace", items: [{ view: "evidence", label: "Evidence" }] },
            { title: "Analysis", items: [
                { view: "capture", label: "Traffic Capture" },
                { view: "bundle", label: "Endpoint Bundle" }
            ] }
        ];

        groups.forEach(function (group) {
            rail.appendChild(el("div", "atlas-rail-title", group.title));
            group.items.forEach(function (item) {
                var btn = el("button", "atlas-rail-item", item.label);
                btn.type = "button";
                btn.dataset.view = item.view;
                btn.addEventListener("click", function () { showView(item.view); });
                rail.appendChild(btn);
            });
        });
        return rail;
    }

    function init() {
        var layout = el("div", "atlas-layout");
        layout.appendChild(buildRail());

        var main = el("main", "atlas-main");
        main.appendChild(buildEvidencePanel());

        Object.keys(ENGINES).forEach(function (id) {
            var node = document.getElementById(ENGINES[id].root);
            if (node) main.appendChild(node);
        });

        layout.appendChild(main);
        document.body.appendChild(layout);

        renderEvidence();
        showView("evidence");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
