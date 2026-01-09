"use client";

import { useEffect, useState, useRef } from "react";
import { useApi } from "@/providers/ApiProvider";
import { StatCard } from "@/components/StatCard";
import { Gauge, Clock, Hash, Cpu } from "lucide-react";

interface DifficultyData {
  difficulty: string;
  difficultyBits: number;
  lastRetargetBlock: number;
}

export default function MiningPage() {
  const { api, isConnected, isConnecting, error } = useApi();
  const [difficultyData, setDifficultyData] = useState<DifficultyData | null>(null);
  const [blockTimes, setBlockTimes] = useState<number[]>([]);
  const [avgBlockTime, setAvgBlockTime] = useState<number>(0);
  const [currentBlock, setCurrentBlock] = useState<number>(0);
  
  const lastBlockTimeRef = useRef<number>(Date.now());
  const lastBlockNumRef = useRef<number>(0);

  useEffect(() => {
    if (!api || !isConnected) return;

    async function pollMiningData() {
      if (!api) return;
      
      try {
        // Get current block for timing
        const header = await api.rpc.chain.getHeader();
        const blockNum = header.number.toNumber();
        setCurrentBlock(blockNum);
        
        // Track block times
        if (blockNum !== lastBlockNumRef.current && lastBlockNumRef.current > 0) {
          const now = Date.now();
          const timeDiff = (now - lastBlockTimeRef.current) / 1000;
          lastBlockTimeRef.current = now;
          lastBlockNumRef.current = blockNum;

          if (timeDiff > 0 && timeDiff < 120) {
            setBlockTimes((prev) => {
              const updated = [...prev, timeDiff].slice(-30);
              const avg = updated.reduce((a, b) => a + b, 0) / updated.length;
              setAvgBlockTime(Math.round(avg * 10) / 10);
              return updated;
            });
          }
        } else if (lastBlockNumRef.current === 0) {
          lastBlockNumRef.current = blockNum;
          lastBlockTimeRef.current = Date.now();
        }
        
        // Get difficulty data
        if (api.query.difficulty) {
          const difficulty = await api.query.difficulty.difficulty();
          const difficultyBits = await api.query.difficulty.difficultyBits?.() as { toNumber?: () => number } | undefined;
          const lastRetarget = await api.query.difficulty.lastRetargetBlock?.() as { toNumber?: () => number } | undefined;
          
          setDifficultyData({
            difficulty: difficulty.toString(),
            difficultyBits: difficultyBits?.toNumber?.() || 0,
            lastRetargetBlock: lastRetarget?.toNumber?.() || 0,
          });
        }
      } catch (err) {
        console.error("Failed to fetch mining data:", err);
      }
    }

    // Initial fetch
    pollMiningData();

    // Poll every 2 seconds
    const interval = setInterval(pollMiningData, 2000);

    return () => {
      clearInterval(interval);
    };
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

  const blocksSinceRetarget = difficultyData ? currentBlock - difficultyData.lastRetargetBlock : 0;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-neutral-light">Mining</h1>
        <p className="text-neutral-mid text-sm mt-1">Blake3 proof-of-work consensus</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Difficulty"
          value={difficultyData ? formatDifficulty(difficultyData.difficulty) : "—"}
          icon={Gauge}
        />
        <StatCard
          label="Difficulty Bits"
          value={difficultyData?.difficultyBits?.toString() || "—"}
          icon={Cpu}
        />
        <StatCard
          label="Avg Block Time"
          value={avgBlockTime > 0 ? `${avgBlockTime}s` : "—"}
          icon={Clock}
        />
        <StatCard
          label="Since Retarget"
          value={difficultyData ? `${blocksSinceRetarget} blocks` : "—"}
          icon={Hash}
        />
      </div>

      {/* Block Time Chart */}
      <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-neutral-light">Block Times</h2>
          <span className="text-sm text-neutral-mid font-mono">
            Last {blockTimes.length} blocks
          </span>
        </div>
        <div className="h-40 flex items-end gap-[2px]">
          {blockTimes.length === 0 ? (
            <div className="flex-1 flex items-center justify-center">
              <p className="text-neutral-mid text-sm">Waiting for blocks...</p>
            </div>
          ) : (
            blockTimes.map((time, idx) => {
              const maxTime = Math.max(...blockTimes, 30);
              const height = Math.max((time / maxTime) * 100, 4);
              const isRecent = idx === blockTimes.length - 1;
              return (
                <div
                  key={idx}
                  className="flex-1 group relative"
                >
                  <div
                    className={`w-full rounded-t transition-all duration-200 ${
                      isRecent ? "bg-ionosphere" : "bg-ionosphere/50 hover:bg-ionosphere/70"
                    }`}
                    style={{ height: `${height}%` }}
                  />
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-midnight-deep border border-neutral-mid/30 rounded text-xs text-neutral-light font-mono opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none">
                    {time.toFixed(1)}s
                  </div>
                </div>
              );
            })
          )}
        </div>
        <div className="flex justify-between mt-3 text-xs text-neutral-mid">
          <span>← Older</span>
          <span>Newer →</span>
        </div>
      </div>
    </div>
  );
}

function formatDifficulty(diff: string): string {
  const num = BigInt(diff);
  if (num >= BigInt(10 ** 15)) {
    return `${(Number(num) / 10 ** 15).toFixed(2)}P`;
  } else if (num >= BigInt(10 ** 12)) {
    return `${(Number(num) / 10 ** 12).toFixed(2)}T`;
  } else if (num >= BigInt(10 ** 9)) {
    return `${(Number(num) / 10 ** 9).toFixed(2)}G`;
  } else if (num >= BigInt(10 ** 6)) {
    return `${(Number(num) / 10 ** 6).toFixed(2)}M`;
  } else if (num >= BigInt(10 ** 3)) {
    return `${(Number(num) / 10 ** 3).toFixed(2)}K`;
  }
  return diff;
}
