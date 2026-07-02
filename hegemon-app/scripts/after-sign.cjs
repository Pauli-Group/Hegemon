const path = require('node:path');

const isTruthy = (value) => /^(1|true|yes)$/i.test(String(value ?? '').trim());

const hasAppleIdCredentials = () =>
  Boolean(process.env.APPLE_ID && process.env.APPLE_APP_SPECIFIC_PASSWORD && process.env.APPLE_TEAM_ID);

const hasApiKeyCredentials = () =>
  Boolean(process.env.APPLE_API_KEY && process.env.APPLE_API_KEY_ID && process.env.APPLE_API_ISSUER);

module.exports = async function afterSign(context) {
  if (context.electronPlatformName !== 'darwin') {
    return;
  }

  const appPath = path.join(
    context.appOutDir,
    `${context.packager.appInfo.productFilename}.app`
  );
  const requireNotarize = isTruthy(process.env.HEGEMON_REQUIRE_NOTARIZE);
  const appleIdCredentials = hasAppleIdCredentials();
  const apiKeyCredentials = hasApiKeyCredentials();

  if (!appleIdCredentials && !apiKeyCredentials) {
    if (requireNotarize) {
      throw new Error(
        'Apple notarization credentials are required. Set APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, and APPLE_TEAM_ID, or APPLE_API_KEY, APPLE_API_KEY_ID, and APPLE_API_ISSUER.'
      );
    }
    console.warn('Skipping Apple notarization; production macOS releases must run npm run dist:prod with Apple credentials.');
    return;
  }

  const { notarize } = require('@electron/notarize');
  const options = {
    appBundleId: context.packager.appInfo.appId,
    appPath
  };

  if (apiKeyCredentials) {
    Object.assign(options, {
      appleApiKey: process.env.APPLE_API_KEY,
      appleApiKeyId: process.env.APPLE_API_KEY_ID,
      appleApiIssuer: process.env.APPLE_API_ISSUER
    });
  } else {
    Object.assign(options, {
      appleId: process.env.APPLE_ID,
      appleIdPassword: process.env.APPLE_APP_SPECIFIC_PASSWORD,
      teamId: process.env.APPLE_TEAM_ID
    });
  }

  await notarize(options);
};
