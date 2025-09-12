/**
 * Shared Menu Component for MELCloud Dashboard
 * Handles navigation, animations, and admin permissions
 */

class MenuComponent {
    constructor() {
        this.isAdmin = false;
        this.currentPage = this.getCurrentPage();
        this.settingsExpanded = false;
        this.init();
    }

    getCurrentPage() {
        const path = window.location.pathname;
        if (path === '/settings') return 'settings';
        if (path === '/energy') return 'energy';
        if (path === '/') return 'home';
        return 'other';
    }

    init() {
        this.renderMenu();
        this.checkAdminStatus();
        
        // Animate settings menu if on settings page
        if (this.currentPage === 'settings') {
            // Expand immediately without delay
            this.expandSettingsMenu();
        }
    }

    renderMenu() {
        // Instead of replacing the static menu, enhance it with dynamic styling
        this.updateMenuHighlighting();
        this.addNavigationListeners();
    }

    updateMenuHighlighting() {
        // Update navigation link highlighting based on current page
        const homeLink = document.querySelector('a[href="/"]');
        const energyLink = document.querySelector('a[href="/energy"]');
        const settingsLink = document.querySelector('a[href="/settings"]');

        // Reset all links to inactive state
        [homeLink, energyLink, settingsLink].forEach(link => {
            if (link) {
                link.className = 'flex items-center space-x-3 px-3 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-600';
            }
        });

        // Highlight the current page
        let activeLink = null;
        if (this.currentPage === 'home' && homeLink) {
            activeLink = homeLink;
        } else if (this.currentPage === 'energy' && energyLink) {
            activeLink = energyLink;
        } else if (this.currentPage === 'settings' && settingsLink) {
            activeLink = settingsLink;
        }

        if (activeLink) {
            activeLink.className = 'flex items-center space-x-3 px-3 py-2 rounded-lg bg-primary-500 text-white';
        }
    }

    async checkAdminStatus() {
        try {
            const response = await fetch('/api/users');
            if (response.ok) {
                this.isAdmin = true;
                this.showAdminMenuItems();
            }
        } catch (error) {
            console.log('Not admin or error checking status');
        }
    }

    showAdminMenuItems() {
        const adminElements = ['users-submenu', 'melcloud-submenu'];
        adminElements.forEach(id => {
            const elem = document.getElementById(id);
            if (elem) elem.style.display = 'flex';
        });
    }

    expandSettingsMenu() {
        const submenu = document.getElementById('settings-submenu');
        if (submenu && !this.settingsExpanded) {
            submenu.classList.remove('collapsed');
            submenu.classList.add('expanded');
            this.settingsExpanded = true;
        }
    }

    collapseSettingsMenu() {
        const submenu = document.getElementById('settings-submenu');
        if (submenu && this.settingsExpanded) {
            submenu.classList.remove('expanded');
            submenu.classList.add('collapsed');
            this.settingsExpanded = false;
        }
    }

    addNavigationListeners() {
        // Add click listeners to navigation links to collapse submenu when leaving settings
        const navLinks = document.querySelectorAll('nav a[href]');
        navLinks.forEach(link => {
            link.addEventListener('click', (event) => {
                const href = link.getAttribute('href');
                
                // Only collapse if we're currently on settings and navigating away
                if (this.currentPage === 'settings' && href !== '/settings' && href !== '#') {
                    event.preventDefault();
                    this.collapseSettingsMenu();
                    
                    // Allow animation to play for 200ms before navigating
                    setTimeout(() => {
                        window.location.href = href;
                    }, 200);
                }
            });

            // Prefetch on intent for faster navigation
            const prefetch = () => {
                const href = link.getAttribute('href') || '';
                try {
                    if (href === '/energy') {
                        fetch('/api/energy-stats', { credentials: 'same-origin' }).catch(() => {});
                    } else if (href === '/schedules') {
                        fetch('/api/schedules?active_only=true', { credentials: 'same-origin' }).catch(() => {});
                        fetch('/api/next-schedules', { credentials: 'same-origin' }).catch(() => {});
                    } else if (href === '/data-history') {
                        fetch('/api/data/history?limit=20', { credentials: 'same-origin' }).catch(() => {});
                    } else if (href === '/' || href === '/dashboard') {
                        fetch('/api/data', { credentials: 'same-origin' }).catch(() => {});
                        fetch('/api/weather', { credentials: 'same-origin' }).catch(() => {});
                    }
                } catch {}
            };
            ['mouseenter', 'focus', 'touchstart'].forEach(ev => link.addEventListener(ev, prefetch, { passive: true }));
        });
    }

    showTab(tabName) {
        // Only works on settings page - delegate to page-specific function
        if (this.currentPage === 'settings' && window.showTab) {
            window.showTab(tabName);
        }
    }
}

// CSS for animations
const menuCSS = `
    .submenu-container {
        overflow: hidden;
        transition: max-height 0.25s cubic-bezier(0.4, 0, 0.2, 1), 
                    opacity 0.2s cubic-bezier(0.4, 0, 0.2, 1), 
                    margin-top 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    .submenu-container.collapsed {
        max-height: 0;
        opacity: 0;
        margin-top: 0;
    }
    
    .submenu-container.expanded {
        max-height: 200px;
        opacity: 1;
        margin-top: 0.5rem;
    }
`;

// Inject CSS
const style = document.createElement('style');
style.textContent = menuCSS;
document.head.appendChild(style);

// Initialize menu when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    window.menuComponent = new MenuComponent();
});
