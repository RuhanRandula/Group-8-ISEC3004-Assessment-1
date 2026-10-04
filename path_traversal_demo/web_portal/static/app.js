function filterDocuments() {
    const searchInput = document.getElementById("documentSearch");
    const searchTerm = searchInput.value.toLowerCase();

    const cards = document.querySelectorAll(".document-card");

    cards.forEach(function(card) {
        const documentName = card
            .querySelector(".document-info h3")
            .textContent
            .toLowerCase();

        card.style.display = documentName.includes(searchTerm)
            ? "flex"
            : "none";
    });
}
