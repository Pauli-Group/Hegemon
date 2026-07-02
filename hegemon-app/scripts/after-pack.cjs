const { execFileSync } = require('node:child_process');
const path = require('node:path');

module.exports = async function afterPack(context) {
  if (context.electronPlatformName !== 'darwin') {
    return;
  }

  const plistPath = path.join(context.appOutDir, 'Hegemon.app', 'Contents', 'Info.plist');
  execFileSync('/usr/bin/plutil', [
    '-replace',
    'NSAppTransportSecurity.NSAllowsArbitraryLoads',
    '-bool',
    'NO',
    plistPath
  ]);
  execFileSync('/usr/bin/plutil', [
    '-replace',
    'NSAppTransportSecurity.NSAllowsLocalNetworking',
    '-bool',
    'YES',
    plistPath
  ]);
};
