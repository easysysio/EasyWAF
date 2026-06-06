// EasyWAF — sidebar & UI initialisation

// ── Theme handling ────────────────────────────────────────
// The current theme is applied as early as possible by an inline script
// in the page <head> (to avoid a flash of the wrong theme). This file
// wires up the toggle button and persists the choice in localStorage.
(function () {
    function currentTheme() {
        return document.documentElement.getAttribute('data-theme') || 'dark';
    }
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        try { localStorage.setItem('easywaf-theme', theme); } catch (e) {}
        updateToggleIcon(theme);
    }
    function updateToggleIcon(theme) {
        var icon = document.getElementById('themeToggleIcon');
        if (!icon) return;
        // Show the icon for the theme you would switch TO.
        icon.className = theme === 'dark' ? 'fa fa-sun-o' : 'fa fa-moon-o';
    }

    // Exposed for the toggle button's onclick.
    window.toggleTheme = function () {
        applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
    };

    // Sync the icon once the DOM is ready.
    document.addEventListener('DOMContentLoaded', function () {
        updateToggleIcon(currentTheme());
    });
})();

// ── Sidebar & alerts ──────────────────────────────────────
$(document).ready(function () {
    // MetisMenu sidebar
    if ($.fn.metisMenu) {
        $('#side-menu').metisMenu();
    }

    // Auto-dismiss alerts after 5 seconds
    window.setTimeout(function () {
        $('.alert-dismissible').fadeTo(500, 0).slideUp(500);
    }, 5000);
});
