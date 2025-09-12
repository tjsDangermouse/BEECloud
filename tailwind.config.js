/**
 * Tailwind CSS configuration for MELCloud Dashboard
 * Build command (no install needed):
 *   npx tailwindcss -i ./src/styles/tailwind.css -o ./static/css/tailwind.css --minify
 */
module.exports = {
  darkMode: 'class',
  content: [
    './templates/**/*.html',
    './static/js/**/*.js'
  ],
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
        }
      }
    }
  },
  plugins: []
};

