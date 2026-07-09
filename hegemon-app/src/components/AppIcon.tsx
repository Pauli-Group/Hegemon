import type { AppIconName } from '../lib/appTypes';

export const AppIcon = ({ name }: { name: AppIconName }) => {
  const sharedProps = {
    viewBox: '0 0 24 24',
    fill: 'none',
    'aria-hidden': true
  };

  const paths: Record<AppIconName, JSX.Element> = {
    overview: (
      <>
        <path d="M3.5 11.5 12 4l8.5 7.5" />
        <path d="M5.5 10.5v8h13v-8" />
        <path d="M9.5 18.5v-5h5v5" />
      </>
    ),
    node: (
      <>
        <path d="M12 4.5v5" />
        <path d="M6.5 14.5h11" />
        <path d="M6.5 14.5v5" />
        <path d="M17.5 14.5v5" />
        <path d="M9.5 9.5h5v5h-5z" />
        <path d="M4.5 19.5h4" />
        <path d="M15.5 19.5h4" />
      </>
    ),
    wallet: (
      <>
        <path d="M4 7.5h14.5a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5.5A2.5 2.5 0 0 1 3 17V8.5a1 1 0 0 1 1-1Z" />
        <path d="M4.5 7.5 16 4.5" />
        <path d="M16.5 13.5h4" />
      </>
    ),
    send: (
      <>
        <path d="M4 5.5 20 12 4 18.5l3-6.5-3-6.5Z" />
        <path d="M7 12h7" />
      </>
    ),
    disclosure: (
      <>
        <path d="M6.5 3.5h8l4 4v13h-12z" />
        <path d="M14.5 3.5v4h4" />
        <path d="M8.5 14c1.2-1.7 2.4-2.5 3.5-2.5s2.3.8 3.5 2.5c-1.2 1.7-2.4 2.5-3.5 2.5S9.7 15.7 8.5 14Z" />
        <path d="M11.25 14a.75.75 0 1 0 1.5 0 .75.75 0 0 0-1.5 0Z" />
      </>
    ),
    console: (
      <>
        <path d="M4.5 6.5h15v11h-15z" />
        <path d="m7 10 2.5 2L7 14" />
        <path d="M12 14h4" />
      </>
    ),
    height: (
      <>
        <path d="M4 16.5 8.5 12l3 3 8-8" />
        <path d="M15.5 7.5h4v4" />
      </>
    ),
    target: (
      <>
        <path d="M12 4v3" />
        <path d="M12 17v3" />
        <path d="M4 12h3" />
        <path d="M17 12h3" />
        <path d="M7.5 12a4.5 4.5 0 1 0 9 0 4.5 4.5 0 0 0-9 0Z" />
      </>
    ),
    sync: (
      <>
        <path d="M18.5 8.5A7 7 0 0 0 6 7l-1.5 2.5" />
        <path d="M4.5 7.5v2h2" />
        <path d="M5.5 15.5A7 7 0 0 0 18 17l1.5-2.5" />
        <path d="M19.5 16.5v-2h-2" />
      </>
    ),
    key: (
      <>
        <path d="M4.5 14.5a4 4 0 1 0 3-3.9" />
        <path d="M11.5 12.5 20 4" />
        <path d="M16.5 7.5 18 9" />
        <path d="M14.5 9.5 16 11" />
      </>
    ),
    peers: (
      <>
        <path d="M8 10a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z" />
        <path d="M16 10a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z" />
        <path d="M4.5 19c.7-3.4 2-5 3.5-5s2.8 1.6 3.5 5" />
        <path d="M12.5 19c.7-3.4 2-5 3.5-5s2.8 1.6 3.5 5" />
      </>
    ),
    mining: (
      <>
        <path d="m5 19 9.5-9.5" />
        <path d="M12 7.5 16.5 3 21 7.5l-4.5 4.5" />
        <path d="M8.5 15.5 10 17" />
      </>
    ),
    endpoint: (
      <>
        <path d="M6.5 7.5h11v9h-11z" />
        <path d="M9 20h6" />
        <path d="M12 16.5V20" />
        <path d="M4 10h2.5" />
        <path d="M17.5 10H20" />
      </>
    )
  };

  return (
    <svg className={`app-icon app-icon-${name}`} {...sharedProps}>
      {paths[name]}
    </svg>
  );
};

