document
    .getElementById("loginForm")
    .addEventListener("submit", function (event) {

        event.preventDefault();

        const studentId =
            document.getElementById("studentId").value.trim();

        const password =
            document.getElementById("password").value.trim();

        if (studentId === "" || password === "") {
            return;
        }

        window.location.href = "dashboard.html";
    });