import type { EmptyStateIconName } from '../lib/appTypes';

export const EmptyStateIcon = ({ name }: { name: EmptyStateIconName }) => {
  const sharedProps = {
    className: `empty-state-glyph ${name}`,
    viewBox: '0 0 48 48',
    fill: 'none',
    'aria-hidden': true
  };

  if (name === 'terminal') {
    return (
      <svg {...sharedProps}>
        <path d="M11 14.5h26a3 3 0 0 1 3 3v17a3 3 0 0 1-3 3H11a3 3 0 0 1-3-3v-17a3 3 0 0 1 3-3Z" />
        <path d="M15 22.5 20 27l-5 4.5" />
        <path d="M24 31.5h9" />
      </svg>
    );
  }

  if (name === 'contacts') {
    return (
      <svg {...sharedProps}>
        <path d="M13 10.5h18a4 4 0 0 1 4 4v19a4 4 0 0 1-4 4H13a3 3 0 0 1-3-3v-21a3 3 0 0 1 3-3Z" />
        <path d="M35 17h4M35 24h4M35 31h4" />
        <path d="M18 22.5a4 4 0 1 0 8 0 4 4 0 0 0-8 0Z" />
        <path d="M15.5 32.5c1.7-3.1 4.1-4.7 6.5-4.7s4.8 1.6 6.5 4.7" />
      </svg>
    );
  }

  if (name === 'disclosure') {
    return (
      <svg {...sharedProps}>
        <path d="M14 8.5h14l8 8v20a3 3 0 0 1-3 3H14a3 3 0 0 1-3-3v-25a3 3 0 0 1 3-3Z" />
        <path d="M28 8.5v8h8" />
        <path d="M16.5 27c2.3-3.1 4.8-4.7 7.5-4.7s5.2 1.6 7.5 4.7c-2.3 3.1-4.8 4.7-7.5 4.7s-5.2-1.6-7.5-4.7Z" />
        <path d="M22 27a2 2 0 1 0 4 0 2 2 0 0 0-4 0Z" />
      </svg>
    );
  }

  return (
    <svg {...sharedProps}>
      <path d="M12 18.5h20" />
      <path d="m30 13.5 5 5-5 5" />
      <path d="M36 29.5H16" />
      <path d="m18 24.5-5 5 5 5" />
      <path d="M13 11.5h9" opacity="0.55" />
      <path d="M26 36.5h9" opacity="0.55" />
    </svg>
  );
};

