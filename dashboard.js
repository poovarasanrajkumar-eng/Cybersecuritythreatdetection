/* ===== BASE STYLES ===== */
:root {
    /* Color Palette */
    --primary-gradient: linear-gradient(135deg, #00d4ff, #7b2cbf);
    --secondary-gradient: linear-gradient(135deg, #1a1a2e, #16213e);
    --background-dark: #0f0f23;
    --surface-color: rgba(255, 255, 255, 0.05);
    --border-color: rgba(255, 255, 255, 0.1);
    --text-primary: #ffffff;
    --text-secondary: rgba(255, 255, 255, 0.7);
    --text-muted: rgba(255, 255, 255, 0.5);

    /* Threat Colors */
    --threat-critical: #991b1b;
    --threat-high: #ef4444;
    --threat-medium: #f59e0b;
    --threat-low: #eab308;
    --threat-safe: #22c55e;
    --accent-blue: #00d4ff;
    --accent-purple: #7b2cbf;

    /* Spacing */
    --spacing-xs: 0.25rem;
    --spacing-sm: 0.5rem;
    --spacing-md: 1rem;
    --spacing-lg: 1.5rem;
    --spacing-xl: 2rem;
    --spacing-2xl: 3rem;

    /* Border Radius */
    --radius-sm: 8px;
    --radius-md: 10px;
    --radius-lg: 15px;
    --radius-xl: 20px;
    --radius-full: 9999px;

    /* Shadows */
    --shadow-sm: 0 2px 10px rgba(0, 0, 0, 0.1);
    --shadow-md: 0 5px 15px rgba(0, 0, 0, 0.2);
    --shadow-lg: 0 10px 25px rgba(0, 0, 0, 0.3);
    --shadow-xl: 0 25px 45px rgba(0, 0, 0, 0.4);

    /* Transitions */
    --transition-fast: 0.2s ease;
    --transition-normal: 0.3s ease;
    --transition-slow: 0.5s ease;

    /* Typography */
    --font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    --font-size-xs: 0.8rem;
    --font-size-sm: 0.9rem;
    --font-size-base: 1rem;
    --font-size-lg: 1.1rem;
    --font-size-xl: 1.3rem;
    --font-size-2xl: 1.8rem;
    --font-size-3xl: 2.5rem;
}

/* ===== RESET & BASE ===== */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {
    font-family: var(--font-family);
    background: var(--background-dark);
    color: var(--text-primary);
    line-height: 1.6;
    overflow-x: hidden;
}

/* ===== TYPOGRAPHY ===== */
h1, h2, h3, h4, h5, h6 {
    font-weight: 600;
    line-height: 1.2;
    margin-bottom: var(--spacing-sm);
}

h1 { font-size: var(--font-size-3xl); }
h2 { font-size: var(--font-size-2xl); }
h3 { font-size: var(--font-size-xl); }
h4 { font-size: var(--font-size-lg); }

p {
    margin-bottom: var(--spacing-md);
    color: var(--text-secondary);
}

strong {
    font-weight: 600;
    color: var(--text-primary);
}

/* ===== UTILITIES ===== */
.text-center { text-align: center; }
.text-left { text-align: left; }
.text-right { text-align: right; }

.hidden { display: none !important; }
.visible { display: block !important; }

.sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
}

/* ===== ANIMATIONS ===== */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

@keyframes slideInLeft {
    from { opacity: 0; transform: translateX(-30px); }
    to { opacity: 1; transform: translateX(0); }
}

@keyframes slideInRight {
    from { opacity: 0; transform: translateX(30px); }
    to { opacity: 1; transform: translateX(0); }
}

@keyframes pulse {
    0%, 100% { opacity: 0.7; }
    50% { opacity: 1; }
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

@keyframes backgroundShift {
    0% { transform: translateX(-5px) translateY(-5px); }
    100% { transform: translateX(5px) translateY(5px); }
}

.fade-in { animation: fadeIn 0.6s ease-out; }
.slide-in-left { animation: slideInLeft 0.6s ease-out; }
.slide-in-right { animation: slideInRight 0.6s ease-out; }

/* ===== LOADING SPINNER ===== */
.loading-spinner {
    display: inline-block;
    width: 16px;
    height: 16px;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-radius: 50%;
    border-top-color: var(--text-primary);
    animation: spin 1s linear infinite;
    margin-right: var(--spacing-sm);
}

.loading-spinner.large {
    width: 32px;
    height: 32px;
    border-width: 3px;
}

/* ===== RESPONSIVE DESIGN ===== */
@media (max-width: 1200px) {
    :root {
        --font-size-3xl: 2rem;
        --font-size-2xl: 1.5rem;
    }
}

@media (max-width: 768px) {
    :root {
        --spacing-lg: 1rem;
        --spacing-xl: 1.5rem;
        --spacing-2xl: 2rem;
    }

    body {
        font-size: var(--font-size-sm);
    }
}

@media (max-width: 480px) {
    :root {
        --font-size-3xl: 1.8rem;
        --font-size-2xl: 1.3rem;
        --spacing-md: 0.75rem;
        --spacing-lg: 1rem;
    }
}
