document.addEventListener("DOMContentLoaded", function () {
    /* ── Sidebar toggle for mobile ────────────────────────────── */
    var sidebar = document.getElementById("sidebar");
    var openBtn = document.getElementById("sidebar-open");
    var closeBtn = document.getElementById("sidebar-close");

    if (openBtn) {
        openBtn.addEventListener("click", function () {
            sidebar.classList.add("open");
        });
    }
    if (closeBtn) {
        closeBtn.addEventListener("click", function () {
            sidebar.classList.remove("open");
        });
    }

    /* ── Smooth scroll to sub-technique anchors ───────────────── */
    if (window.location.hash) {
        var target = document.querySelector(window.location.hash);
        if (target) {
            setTimeout(function () {
                target.scrollIntoView({ behavior: "smooth", block: "start" });
            }, 100);
        }
    }

    /* ── Sortable tables ──────────────────────────────────────── */
    var DIFF_ORDER = { easy: 0, medium: 1, hard: 2, insane: 3, unknown: 4, "": 5 };

    document.querySelectorAll("table.sortable").forEach(function (table) {
        var headers = table.querySelectorAll("th[data-sort]");
        headers.forEach(function (th, colIdx) {
            th.classList.add("sortable-header");
            th.addEventListener("click", function () {
                sortTable(table, th, colIdx);
            });
        });
    });

    function sortTable(table, th, colIdx) {
        var tbody = table.querySelector("tbody");
        var rows = Array.from(tbody.querySelectorAll("tr"));
        var sortType = th.getAttribute("data-sort");
        var asc = !th.classList.contains("sort-asc");

        // Clear sort indicators on siblings
        th.closest("tr").querySelectorAll("th").forEach(function (h) {
            h.classList.remove("sort-asc", "sort-desc");
        });
        th.classList.add(asc ? "sort-asc" : "sort-desc");

        rows.sort(function (a, b) {
            var aCell = a.cells[colIdx];
            var bCell = b.cells[colIdx];
            var aVal, bVal;

            if (sortType === "number") {
                aVal = parseFloat(aCell.textContent.replace(/[^\d.-]/g, "")) || 0;
                bVal = parseFloat(bCell.textContent.replace(/[^\d.-]/g, "")) || 0;
            } else if (sortType === "difficulty") {
                aVal = DIFF_ORDER[aCell.textContent.trim().toLowerCase()] ?? 5;
                bVal = DIFF_ORDER[bCell.textContent.trim().toLowerCase()] ?? 5;
            } else {
                aVal = aCell.textContent.trim().toLowerCase();
                bVal = bCell.textContent.trim().toLowerCase();
            }

            if (aVal < bVal) return asc ? -1 : 1;
            if (aVal > bVal) return asc ? 1 : -1;
            return 0;
        });

        rows.forEach(function (row) { tbody.appendChild(row); });
    }
});
