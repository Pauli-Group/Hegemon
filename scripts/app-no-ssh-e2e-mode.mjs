export function parseExecutionMode(args) {
  if (args.length === 0) {
    return 'strict';
  }
  if (args.length === 1 && args[0] === '--review-only') {
    return 'review-only';
  }
  throw new Error('usage: live-app-no-ssh-e2e.mjs [--review-only]');
}
