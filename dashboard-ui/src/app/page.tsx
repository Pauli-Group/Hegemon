"use client";

import { useEffect, useState, useRef } from "react";
import { useApi } from "@/providers/ApiProvider";
import { StatCard } from "@/components/StatCard";
import { BlockList } from "@/components/BlockList";
import { EventFeed } from "@/components/EventFeed";
import { Blocks, Clock, Shield, Zap } from "lucide-react";
import type { BlockInfo, ShieldedEvent } from "@/lib/types";

export default function ExplorerPage() {
  const { api, isConnected, isConnecting, error } = useApi();
  const [lastBlock, setLastBlock] = useState<number>(0);
  const [avgBlockTime, setAvgBlockTime] = useState<number>(0);
  const [poolBalance, setPoolBalance] = useState<string>("0");
  const [commitmentCount, setCommitmentCount] = useState<number>(0);
  const [blocks, setBlocks] = useState<BlockInfo[]>([]);
  const [events, setEvents] = useState<ShieldedEvent[]>([]);
  
  // Track block times for averaging
  const blockTimesRef = useRef<number[]>([]);
  const lastBlockTimeRef = useRef<number>(Date.now());
  const lastBlockNumRef = useRef<number>(0);

  useEffect(() => {
    if (!api || !isConnected) return;

    let pollInterval: NodeJS.Timeout | null = null;

    async function pollChainData() {
      if (!api) return;

      try {
        // Get current block header
        const header = await api.rpc.chain.getHeader();
        const blockNum = header.number.toNumber();
        
        // Only update if block changed
        if (blockNum !== lastBlockNumRef.current) {
          const now = Date.now();
          
          // Calculate block time
          if (lastBlockNumRef.current > 0) {
            const timeDiff = (now - lastBlockTimeRef.current) / 1000;
            if (timeDiff > 0 && timeDiff < 120) {
              blockTimesRef.current.push(timeDiff);
              if (blockTimesRef.current.length > 10) blockTimesRef.current.shift();
              const avg = blockTimesRef.current.reduce((a, b) => a + b, 0) / blockTimesRef.current.length;
              setAvgBlockTime(Math.round(avg));
            }
          }
          
          lastBlockTimeRef.current = now;
          lastBlockNumRef.current = blockNum;
          setLastBlock(blockNum);

          // Add block to list
          const newBlock: BlockInfo = {
            number: blockNum,
            hash: header.hash.toHex(),
            parentHash: header.parentHash.toHex(),
            timestamp: now,
            extrinsicCount: 0,
          };
          setBlocks((prev) => [newBlock, ...prev].slice(0, 20));

          // Fetch events for this block
          try {
            const blockHash = await api.rpc.chain.getBlockHash(blockNum);
            const apiAt = await api.at(blockHash);
            const eventRecords = await apiAt.query.system.events();
            const records = eventRecords as unknown as { event: { section: string; method: string; data: { toJSON: () => unknown }[] } }[];
            
            const shieldedEvents: ShieldedEvent[] = [];
            records.forEach((record, idx) => {
              const { event } = record;
              if (event.section === "shieldedPool") {
                shieldedEvents.push({
                  block: blockNum,
                  eventIndex: idx,
                  method: event.method,
                  data: event.data.map((d) => d.toJSON()) as unknown as Record<string, unknown>,
                });
              }
            });

            if (shieldedEvents.length > 0) {
              setEvents((prev) => [...shieldedEvents, ...prev].slice(0, 50));
            }
          } catch {
            // Events fetch may fail for older blocks
          }
        }

        // Get shielded pool stats
        const poolBal = await api.query.shieldedPool.poolBalance();
        const rawBalance = BigInt(poolBal.toString());
        // HGM uses 8 decimal places (like Bitcoin satoshis), not 12
        const wholeUnits = Number(rawBalance) / 1e8;
        setPoolBalance(wholeUnits.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }));

        const commitIdx = await api.query.shieldedPool.commitmentIndex();
        setCommitmentCount((commitIdx as unknown as { toNumber: () => number }).toNumber());

      } catch (err) {
        console.error("Poll error:", err);
      }
    }

    // Initial fetch
    pollChainData();

    // Poll every 2 seconds (faster than block time to catch new blocks quickly)
    pollInterval = setInterval(pollChainData, 2000);

    return () => {
      if (pollInterval) clearInterval(pollInterval);
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

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Last Block"
          value={`#${lastBlock.toLocaleString()}`}
          icon={Blocks}
        />
        <StatCard
          label="Avg Block Time"
          value={`${avgBlockTime}s`}
          icon={Clock}
        />
        <StatCard
          label="Shielded Supply"
          value={`${poolBalance} HGM`}
          icon={Shield}
        />
        <StatCard
          label="Commitments"
          value={commitmentCount.toLocaleString()}
          icon={Zap}
        />
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <BlockList blocks={blocks} />
        <EventFeed events={events} />
      </div>
    </div>
  );
}
