/**
 * Shared UI Functions for MELCloud Dashboard
 * These functions are used across multiple templates and are defined globally
 * to work with onclick handlers in HTML templates.
 */

// Global logout function
window.logout = async function() {
    try {
        const response = await fetch('/logout', {
            method: 'GET',
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            // Clear cached user info
            localStorage.removeItem('currentUserName');
            // Redirect to login page
            window.location.href = '/login';
        } else {
            console.error('Logout failed');
            // Force redirect anyway for security
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Logout error:', error);
        // Force redirect for security
        window.location.href = '/login';
    }
};

// Global user info display function
window.displayUserInfo = async function() {
    // First, try to load from localStorage to avoid flash
    const cachedUser = localStorage.getItem('currentUserName');
    if (cachedUser) {
        const userInfoElement = document.getElementById('user-info');
        const userInfoMobileElement = document.getElementById('user-info-mobile');
        if (userInfoElement) userInfoElement.textContent = cachedUser;
        if (userInfoMobileElement) userInfoMobileElement.textContent = cachedUser;
    }
    
    try {
        // Fetch current user information from the server
        const response = await fetch('/api/current-user', {
            credentials: 'same-origin'
        });

        if (!response.ok) {
            setUserInfoFallback();
            return;
        }

        const data = await response.json();
        if (!data.success || !data.user) {
            setUserInfoFallback();
            return;
        }

        const user = data.user;
        const userName = user.username || user.email || 'User';

        // Cache the username for future page loads
        localStorage.setItem('currentUserName', userName);

        // Update both desktop and mobile user info elements
        const userInfoElement = document.getElementById('user-info');
        const userInfoMobileElement = document.getElementById('user-info-mobile');

        if (userInfoElement) {
            userInfoElement.textContent = userName;
        }
        if (userInfoMobileElement) {
            userInfoMobileElement.textContent = userName;
        }
    } catch (error) {
        console.error('Error fetching user info:', error);
        setUserInfoFallback();
    }
};

// Helper function for user info fallback
function setUserInfoFallback() {
    const userInfoElement = document.getElementById('user-info');
    const userInfoMobileElement = document.getElementById('user-info-mobile');
    
    if (userInfoElement) {
        userInfoElement.textContent = 'User';
    }
    if (userInfoMobileElement) {
        userInfoMobileElement.textContent = 'User';
    }
}

// Global desktop dropdown toggle function
window.toggleUserDropdown = function() {
    const dropdown = document.getElementById('user-dropdown');
    const icon = document.getElementById('user-dropdown-icon');
    
    if (!dropdown) return;
    
    if (dropdown.classList.contains('hidden')) {
        dropdown.classList.remove('hidden');
        if (icon) icon.style.transform = 'rotate(180deg)';
        
        // Close dropdown when clicking outside
        document.addEventListener('click', closeDropdownOutside);
    } else {
        dropdown.classList.add('hidden');
        if (icon) icon.style.transform = 'rotate(0deg)';
        document.removeEventListener('click', closeDropdownOutside);
    }
};

// Global mobile dropdown toggle function
window.toggleUserDropdownMobile = function() {
    const dropdown = document.getElementById('user-dropdown-mobile');
    if (!dropdown) return;
    
    if (dropdown.classList.contains('hidden')) {
        dropdown.classList.remove('hidden');
        
        // Close dropdown when clicking outside
        document.addEventListener('click', closeDropdownMobileOutside);
    } else {
        dropdown.classList.add('hidden');
        document.removeEventListener('click', closeDropdownMobileOutside);
    }
};

// Helper function for closing desktop dropdown when clicking outside
function closeDropdownOutside(event) {
    const dropdown = document.getElementById('user-dropdown');
    const button = dropdown?.previousElementSibling;
    
    if (dropdown && !dropdown.contains(event.target) && 
        button && !button.contains(event.target)) {
        dropdown.classList.add('hidden');
        const icon = document.getElementById('user-dropdown-icon');
        if (icon) icon.style.transform = 'rotate(0deg)';
        document.removeEventListener('click', closeDropdownOutside);
    }
}

// Helper function for closing mobile dropdown when clicking outside
function closeDropdownMobileOutside(event) {
    const dropdown = document.getElementById('user-dropdown-mobile');
    const button = dropdown?.previousElementSibling;
    
    if (dropdown && !dropdown.contains(event.target) && 
        button && !button.contains(event.target)) {
        dropdown.classList.add('hidden');
        document.removeEventListener('click', closeDropdownMobileOutside);
    }
}
