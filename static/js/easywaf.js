// EasyWAF — sidebar & UI initialisation
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
