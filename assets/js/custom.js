// custom.js

window.addEventListener('unhandledrejection', function(event) {
    console.warn('Unhandled promise rejection:', event.reason);
});

document.addEventListener('DOMContentLoaded', function () {
    // Initialize Clipboard.js if #copyBtn exists
    initializeClipboard();

    // Handle Form Submission
    handleFormSubmission();

    // Initialize Password Toggle
    initializePasswordToggle();

    // Observe changes to mainContent to initialize Clipboard.js when needed
    observeMainContent();
});

// Function to Initialize Clipboard.js
function initializeClipboard() {
    const copyBtn = document.getElementById('copyBtn');
    if (!copyBtn) {
        console.log('#copyBtn not found in the DOM. Clipboard.js will not be initialized on this page.');
        return;
    }

    if (typeof ClipboardJS === 'undefined') {
        console.error('ClipboardJS is not loaded.');
        return;
    }

    console.log('ClipboardJS Initialized...');
    const clipboard = new ClipboardJS(copyBtn);

    clipboard.on('success', function(e) {
        console.log('Text copied:', e.text);
        updateButtonState();
        e.clearSelection();
    });

    clipboard.on('error', function(e) {
        console.error('Copy failed:', e);
        showToast('Copy failed. Please try manually.');
    });

    // Prevent event from propagating to Bootstrap's listeners
    copyBtn.addEventListener('click', function(event) {
        console.log('Copy button clicked - Clipboard.js handled');
        event.stopPropagation(); // Prevent Bootstrap's click listeners from firing
    });
}

// Function to Handle Form Submission
function handleFormSubmission() {
    const form = document.getElementById('secureMessageForm');
    if (form) {
        form.addEventListener('submit', async function (event) {
            event.preventDefault();
            const formData = new FormData(form);
            const csrfToken = formData.get('_csrf');

            try {
                const response = await fetch(form.action, {
                    method: 'POST',
                    headers: {
                        'X-CSRF-Token': csrfToken
                    },
                    body: formData,
                    credentials: 'same-origin'
                });

                if (response.ok) {
                    const contentType = response.headers.get("content-type");
                    if (contentType && contentType.includes("text/html")) {
                        const htmlContent = await response.text();
                        if (!response.url.match(/\.(js|css|json|png|jpg|jpeg|gif|svg)$/i)) {
                            // Replace the mainContent's innerHTML instead of the entire document
                            const mainContent = document.getElementById('mainContent');
                            if (mainContent) {
                                mainContent.innerHTML = htmlContent;
                                window.history.pushState({}, '', response.url);
                            } else {
                                console.error("mainContent container not found.");
                                showToast("An unexpected error occurred.");
                            }
                        } else {
                            console.error("Unexpected URL for HTML content:", response.url);
                            showToast("Unexpected response URL");
                        }
                    } else {
                        console.error("Unexpected content type:", contentType);
                        showToast("Unexpected response type from server");
                    }
                } else {
                    const contentType = response.headers.get("content-type");

                    if (response.status === 400) {
                        showToast("Bad Request: Please check your input.");
                    } else if (response.status === 403) {
                        showToast("Forbidden: You don't have permission to do that.");
                    } else if (contentType && contentType.includes("application/json")) {
                        const errorData = await response.json();
                        console.error("Error response:", errorData);
                        showToast(errorData.error || "An unexpected error occurred");
                    } else {
                        const errorText = await response.text();
                        console.error("Error response:", errorText);
                        showToast("An unexpected error occurred (non-JSON response)");
                    }
                }
            } catch (error) {
                console.error("Submission error:", error);
                showToast(`Network error: ${error.message}`);
            }
        });
    }
}

// Function to Initialize Password Toggle
function initializePasswordToggle() {
    console.log('Initializing Password Toggle');
    const passwordCheckbox = document.getElementById('enable_password');
    const passwordContainer = document.getElementById('password-container');

    if (passwordCheckbox && passwordContainer) {
        passwordCheckbox.addEventListener('change', function () {
            console.log('Password Checkbox Changed:', this.checked);
            if (this.checked) {
                passwordContainer.classList.remove('hidden');
                passwordContainer.classList.add('visible');
            } else {
                passwordContainer.classList.remove('visible');
                passwordContainer.classList.add('hidden');
            }
        });
    } else {
        console.error('Password Checkbox or Container not found.');
    }
}

// Function to Observe Changes to mainContent
function observeMainContent() {
    const mainContent = document.getElementById('mainContent');
    if (!mainContent) {
        console.error('mainContent container not found for MutationObserver.');
        return;
    }

    const observer = new MutationObserver(function(mutationsList, observer) {
        for (let mutation of mutationsList) {
            if (mutation.type === 'childList') {
                const copyBtn = document.getElementById('copyBtn');
                if (copyBtn && !copyBtn.dataset.clipboardInitialized) {
                    initializeClipboardDynamic(copyBtn);
                }
            }
        }
    });

    observer.observe(mainContent, { childList: true, subtree: true });
}

// Function to Dynamically Initialize Clipboard.js for Newly Added Buttons
function initializeClipboardDynamic(copyBtn) {
    if (!copyBtn) return;

    console.log('Dynamically initializing ClipboardJS for #copyBtn');

    if (typeof ClipboardJS === 'undefined') {
        console.error('ClipboardJS is not loaded.');
        return;
    }

    const clipboard = new ClipboardJS(copyBtn);

    clipboard.on('success', function(e) {
        console.log('Text copied:', e.text);
        updateButtonState();
        e.clearSelection();
    });

    clipboard.on('error', function(e) {
        console.error('Copy failed:', e);
        showToast('Copy failed. Please try manually.');
    });

    // Prevent event from propagating to Bootstrap's listeners
    copyBtn.addEventListener('click', function(event) {
        console.log('Copy button clicked - Clipboard.js handled');
        event.stopPropagation(); // Prevent Bootstrap's click listeners from firing
    });

    // Mark as initialized to prevent duplicate initializations
    copyBtn.dataset.clipboardInitialized = 'true';
}

// Function to Update Button State After Copy
function updateButtonState() {
    const copyBtn = document.getElementById('copyBtn');
    const shareLink = document.getElementById('shareLink');

    if (copyBtn && shareLink) {
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.remove('btn-primary');
        copyBtn.classList.add('btn-success');
        shareLink.classList.add('highlight');

        setTimeout(() => {
            copyBtn.textContent = 'Copy';
            copyBtn.classList.remove('btn-success');
            copyBtn.classList.add('btn-primary');
            shareLink.classList.remove('highlight');
        }, 2000);
    }
}

// Function to Show Toast Notifications
function showToast(message, type = 'danger') { // Default type is 'danger'
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        console.error('Toast container not found.');
        return;
    }

    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');

    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;

    toastContainer.appendChild(toast);

    // Initialize and show the toast
    const bsToast = new bootstrap.Toast(toast, { delay: 5000 });
    bsToast.show();

    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}
