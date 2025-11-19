const ATOMIC_SCALE = 100_000_000;

export function atomicToCoins(atoms: number): number {
  if (!Number.isFinite(atoms)) return 0;
  return atoms / ATOMIC_SCALE;
}

export function coinsToAtomicUnits(coins: number): number {
  if (!Number.isFinite(coins)) return 0;
  return Math.round(coins * ATOMIC_SCALE);
}

export function formatCoinsFromAtomic(atoms: number): string {
  const coins = atomicToCoins(atoms);
  const fixed = coins.toFixed(8);
  const trimmed = fixed.replace(/\.?0+$/, '');
  const [whole, fraction] = trimmed.split('.');
  const wholeFormatted = Number(whole).toLocaleString();
  return fraction ? `${wholeFormatted}.${fraction}` : wholeFormatted;
}
