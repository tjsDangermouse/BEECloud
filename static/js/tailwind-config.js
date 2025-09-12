// Centralized Tailwind CSS configuration
// This file contains the shared Tailwind config used across all pages
if (typeof tailwind !== 'undefined') {
    tailwind.config = {
        darkMode: 'class',
        theme: {
            extend: {
                colors: {
                    primary: {
                        50: '#fef7ed',
                        100: '#fdeacc', 
                        200: '#fad394',
                        300: '#f7b85c',
                        400: '#f59e0b',
                        500: '#f59e0b',
                        600: '#d97706',
                        700: '#b45309',
                        800: '#92400e',
                        900: '#78350f'
                    },
                    success: {
                        400: '#4ade80',
                        500: '#22c55e',
                        600: '#16a34a'
                    },
                    error: {
                        400: '#f87171',
                        500: '#ef4444',
                        600: '#dc2626'
                    },
                    warning: {
                        400: '#facc15',
                        500: '#eab308',
                        600: '#ca8a04'
                    },
                    info: {
                        400: '#60a5fa',
                        500: '#3b82f6',
                        600: '#2563eb'
                    }
                },
                spacing: {
                    '18': '4.5rem',
                    '88': '22rem',
                    '112': '28rem',
                    '128': '32rem',
                    '144': '36rem'
                },
                zIndex: {
                    '60': '60',
                    '70': '70',
                    '80': '80',
                    '90': '90',
                    '100': '100'
                }
            }
        },
        plugins: []
    };
}