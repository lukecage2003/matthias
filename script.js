document.addEventListener("DOMContentLoaded", function () {
    // Gestion du scroll pour le header
    window.addEventListener("scroll", function () {
        const header = document.querySelector(".fixed-header");
        if (window.scrollY > 50) {
            header.style.background = "rgba(51, 51, 51, 0.9)";
        } else {
            header.style.background = "#333";
        }
    });

    // Gestion du scroll vers le haut au clic sur le logo
    document.querySelector(".logo").addEventListener("click", function () {
        window.scrollTo({ top: 0, behavior: "smooth" });
    });

    // Gestion de l'upload avec affichage du nom du fichier sélectionné
    const cvInput = document.getElementById("cvInput");
    const confirmationMessage = document.getElementById("confirmationMessage");
    const cvForm = document.getElementById("cvForm");
    const uploadSection = document.querySelector(".upload-section");

    cvInput.addEventListener("change", function () {
        if (cvInput.files.length > 0) {
            confirmationMessage.textContent = `Fichier sélectionné : ${cvInput.files[0].name}`;
            confirmationMessage.style.color = "blue";
            confirmationMessage.style.display = "block";
        }
    });

    // Ajout du drag & drop pour l'upload
    uploadSection.addEventListener("dragover", function (event) {
        event.preventDefault();
        uploadSection.style.border = "2px dashed #ff7e5f";
    });

    uploadSection.addEventListener("dragleave", function () {
        uploadSection.style.border = "none";
    });

    uploadSection.addEventListener("drop", function (event) {
        event.preventDefault();
        uploadSection.style.border = "none";
        const files = event.dataTransfer.files;
        if (files.length > 0) {
            cvInput.files = files;
            confirmationMessage.textContent = `Fichier déposé : ${files[0].name}`;
            confirmationMessage.style.color = "blue";
            confirmationMessage.style.display = "block";
        }
    });

    // Gestion de l'envoi du formulaire avec animation
    cvForm.addEventListener("submit", function (event) {
        event.preventDefault();
        confirmationMessage.textContent = "Votre CV a été envoyé avec succès !";
        confirmationMessage.style.color = "green";
        confirmationMessage.style.opacity = "0";
        confirmationMessage.style.display = "block";
        setTimeout(() => {
            confirmationMessage.style.transition = "opacity 1s ease-in-out";
            confirmationMessage.style.opacity = "1";
        }, 100);
    });
});
ducument.addEventListener("DOMContentLoaded", function () {
    const burger = document.querySelector(".burger-menu");
    const navlinks = document.querySelector(".nav-links");

    burger.addEventListener("click", function () {
        navlinks.classList.toggle("active");
    });
});

