// FILE: dom_xss_demo/static/js/board.js
// ISEC3004 Assignment 1 — Vulnerability 1: DOM-based XSS
// Member 2 — MITIGATED VERSION

// The vulnerable version used innerHTML to display the search query
// This version uses textContent so the query is treated as plain text

// Vulnerable:
// banner.innerHTML = 'Showing results for: "<strong>' + query + '</strong>"';

// Fixed:
// banner.textContent = 'Showing results for: "' + query + '"';
// textContent prevents HTML entered through the URL hash from being
// interpreted and executed by the browser
// A CSP is also added in app.py as an additional security layer

document.addEventListener("DOMContentLoaded", function () {

    // Add event listeners instead of using inline HTML event handlers.
    var form     = document.getElementById("searchForm");
    var clearBtn = document.getElementById("clearBtn");

    if (form)     form.addEventListener("submit", doSearch);
    if (clearBtn) clearBtn.addEventListener("click", clearSearch);

    // Read the search query from the URL hash.
    var raw   = location.hash.substring(1);
    var query = decodeURIComponent(raw);

    // Put the current query into the search box.
    var input = document.getElementById("searchInput");
    if (input && query) input.value = query;

    // Filter the notice cards using the search query.
    if (query) {
        filterNotices(query);
    }

    // Display the search query safely.
    var banner = document.getElementById("search-banner");
    if (banner && query) {

        // Use textContent instead of innerHTML so user input
        // is displayed as text and not interpreted as HTML.
        banner.textContent = 'Showing results for: "' + query + '"';
    }

    window.addEventListener("hashchange", function () {
        location.reload();
    });

});


function filterNotices(query) {
    // Filter the notice cards based on the search query.
    var cards     = document.querySelectorAll(".notice-card");
    var noResults = document.getElementById("no-results");
    var q         = query.toLowerCase();
    var matched   = 0;

    cards.forEach(function (card) {
        var title = (card.dataset.title    || "").toLowerCase();
        var cat   = (card.dataset.category || "").toLowerCase();

        if (title.indexOf(q) !== -1 || cat.indexOf(q) !== -1) {
            card.style.display = "";
            matched++;
        } else {
            card.style.display = "none";
        }
    });

    if (noResults) {
        if (matched === 0 && query) {
            noResults.classList.remove("hidden");
        } else {
            noResults.classList.add("hidden");
        }
    }
}


function doSearch(e) {
    e.preventDefault();

    var q = document.getElementById("searchInput").value.trim();

    if (q) {
        location.hash = encodeURIComponent(q);
        location.reload();
    }
}


function clearSearch() {
    document.getElementById("searchInput").value = "";
    history.replaceState(null, "", location.pathname);
    location.reload();
}