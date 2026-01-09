module.exports = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        midnight: '#0E1C36',
        ionosphere: '#1BE7FF',
        amber: '#F5A623',
        proof: '#19B37E',
        guard: '#FF4E4E',
        surface: '#F4F7FB',
        surfaceMuted: '#E1E6EE'
      },
      fontFamily: {
        sans: ['Space Grotesk', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace']
      },
      boxShadow: {
        panel: '0 12px 28px rgba(8, 15, 30, 0.35)'
      }
    }
  },
  plugins: []
};
