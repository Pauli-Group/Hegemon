"use client";

import { useEffect, useState } from "react";
import { useApi } from "@/providers/ApiProvider";
import { StatCard } from "@/components/StatCard";
import { GitBranch, Hash, Coins, TreeDeciduous } from "lucide-react";

interface ShieldedPoolData {
  merkleRoot: string;
  treeSize: number;
  poolBalance: string;
}

export default function ShieldedPoolPage() {
  const { api, isConnected, isConnecting, error } = useApi();
  const [poolData, setPoolData] = useState<ShieldedPoolData | null>(null);
  const [nullifierCount, setNullifierCount] = useState<number>(0);

  useEffect(() => {
    if (!api || !isConnected) return;

    async function fetchPoolData() {
      if (!api || !api.query.shieldedPool) return;

      try {
        // Get merkle root(s)
        const merkleRoots = await api.query.shieldedPool.merkleRoots?.entries?.();
        let latestRoot = "0x" + "0".repeat(96);
        if (merkleRoots && merkleRoots.length > 0) {
          // Get the most recent root
          const lastEntry = merkleRoots[merkleRoots.length - 1];
          if (lastEntry) {
            latestRoot = lastEntry[1].toString();
          }
        }

        // Get tree size from commitment index
        const commitmentIndex = await api.query.shieldedPool.commitmentIndex?.() as { toNumber?: () => number } | undefined;
        const treeSize = commitmentIndex?.toNumber?.() || 0;

        // Get pool balance
        const poolBalance = await api.query.shieldedPool.poolBalance?.();
        const balanceStr = poolBalance?.toString() || "0";

        setPoolData({
          merkleRoot: latestRoot,
          treeSize,
          poolBalance: balanceStr,
        });

        // Count nullifiers
        const nullifiers = await api.query.shieldedPool.nullifiers?.entries?.();
        setNullifierCount(nullifiers?.length || 0);

      } catch (err) {
        console.error("Failed to fetch pool data:", err);
      }
    }

    fetchPoolData();
    const interval = setInterval(fetchPoolData, 5000);

    return () => clearInterval(interval);
  }, [api, isConnected]);

  if (isConnecting) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-ionosphere border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-neutral-mid">Connecting to Hegemon node...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <div className="w-12 h-12 rounded-full bg-guard-rail/20 flex items-center justify-center mx-auto mb-4">
            <span className="text-guard-rail text-2xl">!</span>
          </div>
          <p className="text-guard-rail font-medium mb-2">Connection Error</p>
          <p className="text-neutral-mid text-sm">{error}</p>
        </div>
      </div>
    );
  }

  // HGM uses 8 decimal places (like Bitcoin satoshis)
  const formattedBalance = poolData
    ? (Number(BigInt(poolData.poolBalance)) / 1e8).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })
    : "0";

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-neutral-light">Shielded Pool</h1>
        <p className="text-neutral-mid text-sm mt-1">Privacy-preserving transaction pool</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Tree Size"
          value={poolData?.treeSize.toLocaleString() || "0"}
          icon={TreeDeciduous}
        />
        <StatCard
          label="Nullifiers Used"
          value={nullifierCount.toLocaleString()}
          icon={Hash}
        />
        <StatCard
          label="Shielded Supply"
          value={`${formattedBalance} HGM`}
          icon={Coins}
        />
        <StatCard
          label="Merkle Roots"
          value={(poolData?.merkleRoot !== "0x" + "0".repeat(96)) ? "1" : "0"}
          icon={GitBranch}
        />
      </div>

      {/* Merkle Root Display */}
      <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-neutral-light">Current Merkle Root</h2>
        </div>
        <div className="bg-midnight-deep border border-neutral-mid/10 rounded-lg p-4 overflow-hidden">
          <p className="font-mono text-sm text-ionosphere break-all leading-relaxed">
            {poolData?.merkleRoot || "Loading..."}
          </p>
        </div>
      </div>
    </div>
  );
}
