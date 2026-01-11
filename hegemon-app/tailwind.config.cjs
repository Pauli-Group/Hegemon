module.exports = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        midnight: {
          DEFAULT: '#0E1C36',
          deep: '#070D18',
          light: '#142640'
        },
        ionosphere: {
          DEFAULT: '#1BE7FF',
          muted: '#1BE7FF80',
          dim: '#1BE7FF40'
        },
        amber: {
          DEFAULT: '#F5A623',
          muted: '#F5A62380'
        },
        proof: {
          DEFAULT: '#19B37E',
          muted: '#19B37E80'
        },
        guard: {
          DEFAULT: '#FF4E4E',
          muted: '#FF4E4E80'
        },
        surface: {
          DEFAULT: '#F4F7FB',
          dim: '#F4F7FBD0'
        },
        surfaceMuted: {
          DEFAULT: '#E1E6EE',
          dim: '#E1E6EE80'
        }
      },
      fontFamily: {
        sans: ['Space Grotesk', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace']
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
        'headline': ['1.75rem', { lineHeight: '2rem', letterSpacing: '-0.01em' }],
        'title': ['1.25rem', { lineHeight: '1.5rem', letterSpacing: '-0.005em' }]
      },
      spacing: {
        '18': '4.5rem',
        '22': '5.5rem'
      },
      boxShadow: {
        panel: '0 12px 28px rgba(8, 15, 30, 0.4)',
        'panel-hover': '0 16px 36px rgba(8, 15, 30, 0.5)',
        glow: '0 0 20px rgba(27, 231, 255, 0.15)',
        'glow-strong': '0 0 30px rgba(27, 231, 255, 0.25)'
      },
      backdropBlur: {
        '2xl': '40px',
        '3xl': '64px'
      },
      animation: {
        'fade-in': 'fadeIn 200ms ease-out',
        'slide-up': 'slideUp 300ms ease-out',
        'pulse-slow': 'pulse 3s ease-in-out infinite'
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' }
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' }
        }
      }
    }
  },
  plugins: []
};
