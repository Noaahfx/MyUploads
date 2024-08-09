document.addEventListener('DOMContentLoaded', () => {
//    const sessionTimeout = 1 * 60; // 30 minutes in seconds
//    const warningTime = 0.5 * 60; // Show warning 5 minutes before timeout

    let sessionWarningTimer;
    let sessionExpireTimer;

    function setupTimers() {
        sessionWarningTimer = setTimeout(showSessionWarning, (sessionTimeout - warningTime) * 1000);
        sessionExpireTimer = setTimeout(expireSession, sessionTimeout * 1000);
    }

    function showSessionWarning() {
        $('#sessionWarningModal').modal('show');
    }

    function expireSession() {

        window.location.href = '/logout';
    }

    // Initial setup
    setupTimers();

    // Click event for "No" button in session expiration modal
    document.getElementById('noLogoutBtn').addEventListener('click', () => {
        clearTimeout(sessionWarningTimer); // Clear session warning timer
        clearTimeout(sessionExpireTimer); // Clear session expire timer
        $('#sessionWarningModal').modal('hide'); // Dismiss the modal
        expireSession()
    });

    // Click event for "Yes" button to extend session
    document.getElementById('extendSessionBtn').addEventListener('click', () => {
        $.ajax({
            url: '/extend_session',
            method: 'POST',
            success: (response) => {
                clearTimeout(sessionWarningTimer); // Clear session warning timer
                clearTimeout(sessionExpireTimer); // Clear session expire timer
                setupTimers(); // Reset timers
                $('#sessionWarningModal').modal('hide'); // Dismiss the modal
            },
            error: (xhr, status, error) => {
                console.error('Failed to extend session:', error);
                alert('Failed to extend session. Please try again.');
            }
        });
    });
});