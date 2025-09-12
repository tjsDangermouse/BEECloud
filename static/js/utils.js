// Shared utility functions for MELCloud application
// This file contains commonly used functions across multiple pages

/**
 * Display a flash message to the user
 * @param {string} message - The message to display
 * @param {string} type - The type of message ('success', 'error', 'warning', 'info')
 */
function showFlash(message, type = 'info') {
    // Try to find existing flash containers first
    const flashContainers = [
        document.getElementById('flash-messages'),
        document.getElementById('flash-messages-desktop'),
        document.getElementById('flash-container')
    ].filter(container => container !== null);

    // If no containers exist, create one
    let container;
    if (flashContainers.length === 0) {
        container = document.createElement('div');
        container.id = 'flash-container';
        container.className = 'fixed top-4 right-4 z-[9999] space-y-2';
        document.body.appendChild(container);
        flashContainers.push(container);
    }

    // Create flash message for each container
    flashContainers.forEach(flashContainer => {
        if (!flashContainer) return;

        const flash = document.createElement('div');
        flash.className = `flash-message p-3 rounded-md text-sm transition-all duration-300 transform translate-x-full opacity-0`;
        
        // Set colors based on type
        const colors = {
            success: 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-700',
            error: 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-700',
            warning: 'bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300 border border-yellow-200 dark:border-yellow-700',
            info: 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-700'
        };
        
        flash.className += ` ${colors[type] || colors.info}`;
        flash.innerHTML = `
            <div class="flex items-center justify-between">
                <span>${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-2 text-current opacity-50 hover:opacity-100">
                    <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                    </svg>
                </button>
            </div>
        `;
        
        flashContainer.appendChild(flash);
        
        // Animate in
        setTimeout(() => {
            flash.classList.remove('translate-x-full', 'opacity-0');
        }, 10);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (flash.parentNode) {
                flash.classList.add('translate-x-full', 'opacity-0');
                setTimeout(() => flash.remove(), 300);
            }
        }, 5000);
    });
}

/**
 * Format temperature for display
 * @param {number} temp - Temperature value
 * @param {string} unit - Temperature unit ('°C' or '°F')
 * @returns {string} Formatted temperature string
 */
function formatTemperature(temp, unit = '°C') {
    if (temp === null || temp === undefined || isNaN(temp)) {
        return '--';
    }
    return `${Math.round(temp * 10) / 10}${unit}`;
}

/**
 * Format date for display
 * @param {string|Date} date - Date to format
 * @param {Object} options - Intl.DateTimeFormat options
 * @returns {string} Formatted date string
 */
function formatDate(date, options = {}) {
    if (!date) return '--';
    
    const defaultOptions = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    
    const formatOptions = { ...defaultOptions, ...options };
    
    try {
        const dateObj = typeof date === 'string' ? new Date(date) : date;
        return dateObj.toLocaleDateString('en-GB', formatOptions);
    } catch (error) {
        console.error('Date formatting error:', error);
        return '--';
    }
}

/**
 * Format COP value for display
 * @param {number} cop - COP value
 * @returns {string} Formatted COP string
 */
function formatCOP(cop) {
    if (cop === null || cop === undefined || isNaN(cop)) {
        return '--';
    }
    return Math.round(cop * 100) / 100;
}

/**
 * Format energy consumption for display
 * @param {number} energy - Energy value in kWh
 * @returns {string} Formatted energy string
 */
function formatEnergy(energy) {
    if (energy === null || energy === undefined || isNaN(energy)) {
        return '--';
    }
    return `${Math.round(energy * 100) / 100} kWh`;
}

/**
 * Debounce function to limit API calls
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @param {boolean} immediate - Whether to trigger on leading edge
 * @returns {Function} Debounced function
 */
function debounce(func, wait, immediate) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            timeout = null;
            if (!immediate) func(...args);
        };
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) func(...args);
    };
}

/**
 * Show/hide loading spinner
 * @param {string} elementId - ID of element to show spinner in
 * @param {boolean} show - Whether to show or hide spinner
 */
function toggleLoadingSpinner(elementId, show) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    if (show) {
        element.innerHTML = `
            <div class="flex items-center justify-center p-4">
                <svg class="animate-spin h-8 w-8 text-primary-500" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
            </div>
        `;
    }
}

/**
 * Handle API errors consistently
 * @param {Error} error - The error object
 * @param {string} operation - Description of the operation that failed
 */
function handleAPIError(error, operation = 'Operation') {
    console.error(`${operation} failed:`, error);
    
    let message = `${operation} failed. Please try again.`;
    
    if (error.message && error.message.includes('NetworkError')) {
        message = 'Network error. Please check your connection and try again.';
    } else if (error.message && error.message.includes('401')) {
        message = 'Authentication failed. Please log in again.';
        // Could redirect to login here
    }
    
    showFlash(message, 'error');
}

/**
 * Initialize dark mode based on system preference or localStorage
 */
function initializeDarkMode() {
    // Check localStorage first, then system preference
    const savedTheme = localStorage.getItem('theme');
    const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    if (savedTheme === 'dark' || (!savedTheme && systemDark)) {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
    } else {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
    }
}

/**
 * Toggle dark mode
 */
function toggleDarkMode() {
    const isDark = document.documentElement.classList.contains('dark');
    
    if (isDark) {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
    } else {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
    }
}

// Initialize dark mode on script load
if (typeof window !== 'undefined') {
    document.addEventListener('DOMContentLoaded', initializeDarkMode);
}

// Export functions for module environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        showFlash,
        formatTemperature,
        formatDate,
        formatCOP,
        formatEnergy,
        debounce,
        toggleLoadingSpinner,
        handleAPIError,
        initializeDarkMode,
        toggleDarkMode
    };
}