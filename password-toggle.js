// static/js/password-toggle.js

document.addEventListener('DOMContentLoaded', function() {
    // Cari semua icon eye dengan class toggle-password
    document.querySelectorAll('.toggle-password').forEach(icon => {
        icon.addEventListener('click', function() {
            // Cari input field dalam parent yang sama
            const input = this.parentElement.querySelector('input');
            
            if (!input) return;
            
            // Toggle type
            if (input.type === 'password') {
                input.type = 'text';
                this.classList.remove('fa-eye');
                this.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                this.classList.remove('fa-eye-slash');
                this.classList.add('fa-eye');
            }
        });
    });
});