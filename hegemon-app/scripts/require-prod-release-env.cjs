const hasAppleIdCredentials = () =>
  Boolean(process.env.APPLE_ID && process.env.APPLE_APP_SPECIFIC_PASSWORD && process.env.APPLE_TEAM_ID);

const hasApiKeyCredentials = () =>
  Boolean(process.env.APPLE_API_KEY && process.env.APPLE_API_KEY_ID && process.env.APPLE_API_ISSUER);

if (process.platform === 'darwin' && !hasAppleIdCredentials() && !hasApiKeyCredentials()) {
  console.error(
    'Production macOS releases require Apple notarization credentials. Set APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, and APPLE_TEAM_ID, or APPLE_API_KEY, APPLE_API_KEY_ID, and APPLE_API_ISSUER.'
  );
  process.exit(1);
}
