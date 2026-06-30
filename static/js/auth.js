// ===== AUTHENTICATION MODULE =====

class AuthManager {
    constructor() {
        this.currentEmail = '';
        this.otpSent = false;
    }

    // Utility function to show messages
    showMessage(text, type = 'info', duration = 5000) {
        const messageContainer = document.getElementById('message-container');
        if (!messageContainer) {
            console.error('Message container not found');
            return;
        }

        // Remove existing messages
        const existingMessage = messageContainer.querySelector('.alert');
        if (existingMessage) {
            existingMessage.remove();
        }

        // Create new message
        const messageDiv = document.createElement('div');
        messageDiv.className = `alert alert-${type}`;
        messageDiv.innerHTML = `
            <span class="alert-icon">${this.getAlertIcon(type)}</span>
            <div class="alert-content">
                <div class="alert-description">${text}</div>
            </div>
        `;

        messageContainer.appendChild(messageDiv);

        // Auto-hide success messages
        if (type === 'success' && duration > 0) {
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.remove();
                }
            }, duration);
        }

        // Scroll message into view
        messageDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    getAlertIcon(type) {
        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };
        return icons[type] || 'ℹ️';
    }

    // Email validation
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    // Set loading state for buttons
    setButtonLoading(button, isLoading, originalText) {
        if (isLoading) {
            button.disabled = true;
            button.innerHTML = `<span class="loading-spinner"></span>${originalText === 'Send OTP' ? 'Sending...' : 'Verifying...'}`;
        } else {
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }

    // Send OTP request
    async sendOTP() {
        const emailInput = document.getElementById('email');
        const email = emailInput.value.trim();
        const sendButton = document.getElementById('send-otp-btn');

        // Validation
        if (!email) {
            this.showMessage('⚠️ Please enter a valid email address', 'error');
            emailInput.focus();
            return;
        }

        if (!this.isValidEmail(email)) {
            this.showMessage('⚠️ Please enter a valid email address format', 'error');
            emailInput.focus();
            return;
        }

        this.setButtonLoading(sendButton, true, 'Send OTP');

        try {
            const response = await fetch('/send_otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: email })
            });

            const data = await response.json();

            if (data.success) {
                this.currentEmail = email;
                this.otpSent = true;
                this.showOTPSection();
                this.showMessage(`✅ ${data.message}`, 'success');
            } else {
                this.showMessage(`❌ ${data.message}`, 'error');
            }
        } catch (error) {
            this.showMessage('❌ Network error. Please check your connection and try again.', 'error');
            console.error('Send OTP Error:', error);
        } finally {
            this.setButtonLoading(sendButton, false, 'Send OTP');
        }
    }

    // Verify OTP request
    async verifyOTP() {
        const otpInput = document.getElementById('otp');
        const otp = otpInput.value.trim();
        const verifyButton = document.getElementById('verify-otp-btn');

        // Validation
        if (!otp) {
            this.showMessage('⚠️ Please enter the OTP', 'error');
            otpInput.focus();
            return;
        }

        if (otp.length !== 6) {
            this.showMessage('⚠️ OTP must be 6 digits', 'error');
            otpInput.focus();
            return;
        }

        if (!this.currentEmail) {
            this.showMessage('❌ Session error. Please request a new OTP.', 'error');
            this.showEmailSection();
            return;
        }

        this.setButtonLoading(verifyButton, true, 'Verify & Login');

        try {
            const response = await fetch('/verify_otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: this.currentEmail,
                    otp: otp
                })
            });

            const data = await response.json();

            if (data.success) {
                this.showMessage(`✅ ${data.message}`, 'success');

                // Redirect to dashboard after short delay
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1500);
            } else {
                this.showMessage(`❌ ${data.message}`, 'error');
                // Clear OTP field for retry
                otpInput.value = '';
                otpInput.focus();
            }
        } catch (error) {
            this.showMessage('❌ Network error. Please check your connection and try again.', 'error');
            console.error('Verify OTP Error:', error);
        } finally {
            this.setButtonLoading(verifyButton, false, 'Verify & Login');
        }
    }

    // Show OTP input section
    showOTPSection() {
        const emailSection = document.getElementById('email-section');
        const otpSection = document.getElementById('otp-section');

        if (emailSection && otpSection) {
            emailSection.classList.add('hidden');
            otpSection.classList.remove('hidden');

            // Focus on OTP input
            setTimeout(() => {
                const otpInput = document.getElementById('otp');
                if (otpInput) {
                    otpInput.focus();
                }
            }, 100);
        }
    }

    // Show email input section
    showEmailSection() {
        const emailSection = document.getElementById('email-section');
        const otpSection = document.getElementById('otp-section');
        const messageContainer = document.getElementById('message-container');

        if (emailSection && otpSection) {
            otpSection.classList.add('hidden');
            emailSection.classList.remove('hidden');

            // Clear form state
            const otpInput = document.getElementById('otp');
            if (otpInput) {
                otpInput.value = '';
            }

            // Clear messages
            if (messageContainer) {
                messageContainer.innerHTML = '';
            }

            this.currentEmail = '';
            this.otpSent = false;

            // Focus on email input
            setTimeout(() => {
                const emailInput = document.getElementById('email');
                if (emailInput) {
                    emailInput.focus();
                }
            }, 100);
        }
    }

    // Initialize event listeners
    init() {
        // Send OTP button
        const sendButton = document.getElementById('send-otp-btn');
        if (sendButton) {
            sendButton.addEventListener('click', () => this.sendOTP());
        }

        // Verify OTP button
        const verifyButton = document.getElementById('verify-otp-btn');
        if (verifyButton) {
            verifyButton.addEventListener('click', () => this.verifyOTP());
        }

        // Back button
        const backButton = document.getElementById('back-btn');
        if (backButton) {
            backButton.addEventListener('click', () => this.showEmailSection());
        }

        // Enter key handlers
        const emailInput = document.getElementById('email');
        if (emailInput) {
            emailInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.sendOTP();
                }
            });
        }

        const otpInput = document.getElementById('otp');
        if (otpInput) {
            otpInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.verifyOTP();
                }
            });

            // Auto-format OTP input (numbers only)
            otpInput.addEventListener('input', (e) => {
                let value = e.target.value.replace(/\D/g, '');
                if (value.length > 6) {
                    value = value.substring(0, 6);
                }
                e.target.value = value;
            });
        }

        // Show welcome message
        setTimeout(() => {
            this.showMessage('🛡️ Welcome to NP² Cybersecurity! Enter your email to receive a secure OTP.', 'info');
        }, 500);
    }
}

// Initialize authentication when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    const authManager = new AuthManager();
    authManager.init();

    // Make authManager globally available for inline event handlers if needed
    window.authManager = authManager;
});
