document.querySelectorAll('.password-visibility').forEach(button => {
    const field = document.getElementById(button.getAttribute('aria-controls'));
    const label = field.labels[0].textContent.trim();

    function updateButton() {
        const action = field.type === 'password' ? 'Показать' : 'Скрыть';
        button.textContent = action;
        button.setAttribute('aria-label', `${action}: ${label}`);
    }

    button.addEventListener('click', () => {
        field.type = field.type === 'password' ? 'text' : 'password';
        updateButton();
    });
    updateButton();
    button.hidden = false;
    window.addEventListener('pagehide', () => {
        field.type = 'password';
        updateButton();
    });
});
