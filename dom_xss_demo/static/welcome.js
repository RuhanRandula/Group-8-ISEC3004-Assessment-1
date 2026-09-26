// Read the URL fragment from the browser.
var name = decodeURIComponent(location.hash.substring(1));

// SECURITY FIX:
// Use textContent instead of innerHTML so user-controlled
// input is treated as text rather than interpreted as HTML.
document.getElementById("greeting").textContent = "Hello, " + name + "!";