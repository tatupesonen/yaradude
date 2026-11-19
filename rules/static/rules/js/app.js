// yaradude: progressive enhancement only. Every feature works without this
// file through plain links and form posts.
(function () {
  "use strict";

  // Row selection: a select-all checkbox and a live count on the
  // "Export selected" button.
  function initSelection(form) {
    var all = form.querySelector("[data-select-all]");
    var items = Array.prototype.slice.call(form.querySelectorAll("[data-select-item]"));
    var counter = form.querySelector("[data-selection-count]");
    var label = counter ? counter.textContent : "";
    function update() {
      var checked = items.filter(function (box) { return box.checked; }).length;
      if (all) {
        all.checked = checked > 0 && checked === items.length;
        all.indeterminate = checked > 0 && checked < items.length;
      }
      if (counter) {
        counter.textContent = checked ? label + " (" + checked + ")" : label;
      }
    }
    if (all && items.length) {
      all.hidden = false;
      all.addEventListener("change", function () {
        items.forEach(function (box) { box.checked = all.checked; });
        update();
      });
    }
    items.forEach(function (box) { box.addEventListener("change", update); });
    update();
  }

  // Copy to clipboard: <button data-copy="#textarea-id">.
  function initCopy(button) {
    var source = document.querySelector(button.getAttribute("data-copy"));
    if (!source || !navigator.clipboard) return;
    button.hidden = false;
    var label = button.textContent;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(source.value || source.textContent).then(function () {
        button.textContent = "Copied";
        setTimeout(function () { button.textContent = label; }, 1500);
      });
    });
  }

  // Editor: Tab inserts four spaces (Shift+Tab outdents); Escape then Tab
  // leaves the field, so keyboard users are never trapped.
  function initEditor(area) {
    var escaped = false;
    area.addEventListener("keydown", function (event) {
      if (event.key === "Escape") { escaped = true; return; }
      if (event.key !== "Tab" || escaped || event.altKey || event.ctrlKey || event.metaKey) {
        escaped = false;
        return;
      }
      event.preventDefault();
      var start = area.selectionStart;
      var end = area.selectionEnd;
      var text = area.value;
      var lineStart = text.lastIndexOf("\n", start - 1) + 1;
      if (event.shiftKey) {
        var indent = text.slice(lineStart, lineStart + 4).match(/^ {1,4}/);
        if (indent) {
          var n = indent[0].length;
          area.setRangeText("", lineStart, lineStart + n, "preserve");
          area.setSelectionRange(Math.max(lineStart, start - n), Math.max(lineStart, end - n));
        }
      } else {
        area.setRangeText("    ", start, end, "end");
      }
    });
    // Jump to a diagnostic line: <a data-goto-line="N">.
    document.querySelectorAll("[data-goto-line]").forEach(function (link) {
      link.addEventListener("click", function (event) {
        var line = parseInt(link.getAttribute("data-goto-line"), 10);
        var lines = area.value.split("\n");
        if (!line || line > lines.length) return;
        event.preventDefault();
        var offset = lines.slice(0, line - 1).join("\n").length + (line > 1 ? 1 : 0);
        area.focus();
        area.setSelectionRange(offset, offset + lines[line - 1].length);
      });
    });
  }

  // Drop zone for the multi-file upload: dropped files are put into the
  // real <input type="file">, which the form then posts as usual.
  function initDropzone(zone) {
    var input = zone.querySelector("input[type=file]");
    var list = zone.querySelector("[data-file-list]");
    if (!input) return;
    function show() {
      if (!list) return;
      var names = Array.prototype.map.call(input.files, function (f) { return f.name; });
      list.textContent = names.length
        ? names.length + " file" + (names.length === 1 ? "" : "s") + ": " + names.join(", ")
        : "";
    }
    input.addEventListener("change", show);
    ["dragenter", "dragover"].forEach(function (type) {
      zone.addEventListener(type, function (event) {
        event.preventDefault();
        zone.classList.add("is-dragover");
      });
    });
    ["dragleave", "dragend", "drop"].forEach(function (type) {
      zone.addEventListener(type, function () { zone.classList.remove("is-dragover"); });
    });
    zone.addEventListener("drop", function (event) {
      event.preventDefault();
      if (!event.dataTransfer || !event.dataTransfer.files.length) return;
      try {
        input.files = event.dataTransfer.files;
      } catch (error) {
        return;
      }
      show();
    });
  }

  // Disable submit buttons while a long-running form posts (imports, scans).
  function initBusy(form) {
    form.addEventListener("submit", function (event) {
      var button = form.querySelector("[data-busy-label]");
      if (!button) return;
      // Other submit buttons (e.g. a GET "Check limit") are not long-running.
      if (event.submitter && event.submitter !== button) return;
      var note = form.querySelector(".busy-note");
      setTimeout(function () {
        button.disabled = true;
        button.textContent = button.getAttribute("data-busy-label");
        if (note) note.classList.remove("hidden");
      }, 0);
    });
  }

  // Dropdown menus built on <details>: close on Escape or a click elsewhere.
  function initMenu(menu) {
    document.addEventListener("click", function (event) {
      if (menu.open && !menu.contains(event.target)) menu.open = false;
    });
    menu.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && menu.open) {
        menu.open = false;
        menu.querySelector("summary").focus();
      }
    });
  }

  function init() {
    document.querySelectorAll("details[data-menu]").forEach(initMenu);
    document.querySelectorAll("[data-selection]").forEach(initSelection);
    document.querySelectorAll("[data-copy]").forEach(initCopy);
    document.querySelectorAll("[data-editor]").forEach(initEditor);
    document.querySelectorAll("[data-dropzone]").forEach(initDropzone);
    document.querySelectorAll("form[data-busy]").forEach(initBusy);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
