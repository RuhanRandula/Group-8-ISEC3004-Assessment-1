// FILE: dom_xss_demo/static/js/board.js
// ISEC3004 Assignment 1 — Vulnerability 1: DOM-based XSS
// Member 1 — VULNERABLE VERSION
//

// *VULNERABILITY SUMMARY*
//Reference:MITRE Corporation. (2024). CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'). //Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/79.html

// CWE-79: Improper Neutralisation of Input During Web Page Generation
//
// SOURCE: location.hash
//   The URL fragment (everything after '#') is a DOM source.
//   The browser reads it directly from the address bar and
//   NEVER includes it in the HTTP request sent to the server.
//   This means no server-side log, firewall, or WAF will ever
//   see the attacker's payload — it exists only in the browser.
//
// SINK: innerHTML
//   The query string read from location.hash is passed directly
//   into element.innerHTML with no sanitisation, encoding, or
//   validation of any kind. innerHTML instructs the browser's
//   HTML parser to interpret the string as raw markup. Any HTML
//   tags, event handlers, or script elements in the string are
//   parsed and executed as if they were part of the original page.
//
// ATTACK FLOW:
//   1. Attacker crafts a URL containing a malicious payload in
//      the fragment, e.g.:
//      http://127.0.0.1:5000/board#<img src=x onerror=alert(document.cookie)>
//   2. Victim clicks the link — browser loads /board normally from server.
//   3. The server responds with the clean, unmodified board.html.
//      Flask log shows only: GET /board HTTP/1.1 — no trace of payload.
//   4. board.js runs, reads location.hash, decodes the payload.
//   5. The payload is written into #search-banner via innerHTML.
//   6. The browser's HTML parser creates an <img> element from
//      the attacker's markup and attempts to load src="x".
//   7. The image fails to load (invalid src), triggering onerror.
//   8. The onerror handler is attacker JavaScript — it now runs
//      with full access to the page's DOM, cookies, and session.
//
// NOTE ON EVENT LISTENERS:
//   All event listeners are attached below via addEventListener()
//   rather than inline onclick=/onsubmit= attributes in board.html.
//   This is required for CSP compliance (script-src 'self' blocks
//   inline event handlers the same way it blocks inline <script>).
//   Member 1 follows this pattern even in the vulnerable version so
//   Member 2's mitigation (adding CSP) does not break the search form.


document.addEventListener("DOMContentLoaded", function () {

    // ── Attach form event listeners via addEventListener (not inline) ─────
    var form     = document.getElementById("searchForm");
    var clearBtn = document.getElementById("clearBtn");

    if (form)     form.addEventListener("submit",  doSearch);
    if (clearBtn) clearBtn.addEventListener("click", clearSearch);

    //  Step 1: Read from the SOURCE (location.hash) 
    // location.hash returns the raw fragment including the '#' character.
    // substring(1) strips that leading '#'.
    // decodeURIComponent handles URL-encoded payloads such as
    //   %3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
    // decoding them back into the raw HTML that innerHTML will parse.
    var raw   = location.hash.substring(1);
    var query = decodeURIComponent(raw);

    // Pre-fill the search box from the current hash on page load
    var input = document.getElementById("searchInput");
    if (input && query) input.value = query;

    //  Step 2: Filter notice cards by the search query
    // Safe — only manipulates CSS visibility, never writes query to the DOM.
    if (query) {
        filterNotices(query);
    }

    // Step 3: Display "results for" banner — THE VULNERABLE SINK 
    var banner = document.getElementById("search-banner");
    if (banner && query) {

        
        // VULNERABLE LINE (CWE-79):
        // query comes directly from location.hash — fully attacker-controlled.
        // innerHTML parses its argument as HTML markup.
        // Result: any HTML/JS in query is executed by the browser.
        // Member 2 fixes this by replacing innerHTML with textContent.
        
        banner.innerHTML = 'Showing results for: "<strong>' + query + '</strong>"';
    }

    // Re-run when the user navigates to a new hash (back/forward button)
    window.addEventListener("hashchange", function () {
        location.reload();
    });

});


function filterNotices(query) {
    // Compares the search term against each card's data-title and
    // data-category attributes to show/hide matching notices.
    // Safe: uses only textContent reads and style/class manipulation —
    // the query value is never written into innerHTML anywhere here.
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
        // Toggle the hidden class rather than setting inline style
        if (matched === 0 && query) {
            noResults.classList.remove("hidden");
        } else {
            noResults.classList.add("hidden");
        }
    }
}


function doSearch(e) {
    // Called by the form's submit event listener (attached above via
    // addEventListener — NOT via an inline onsubmit= attribute).
    e.preventDefault();
    var q = document.getElementById("searchInput").value.trim();
    if (q) {
        location.hash = encodeURIComponent(q);
        location.reload();
    }
}


function clearSearch() {
    // Called by the Clear button's click event listener (addEventListener).
    document.getElementById("searchInput").value = "";
    history.replaceState(null, "", location.pathname);
    location.reload();
}
