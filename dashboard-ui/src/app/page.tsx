"use client";

import { useEffect, useState } from "react";
import { useApi } from "@/providers/ApiProvider";
import { StatCard } from "@/components/StatCard";
import { BlockList } from "@/components/BlockList";
import { EventFeed } from "@/components/EventFeed";
import { Blocks, Clock, Coins, Hash } from "lucide-react";
import type { BlockInfo, ShieldedEvent } from "@/lib/types";

export default function ExplorerPage() {
  const { api, isConnected, isConnecting, error } = useApi();
  const [lastBlock, setLastBlock] = useState<number>(0);
  const [avgBlockTime, setAvgBlockTime] = useState<number>(0);
  const [totalIssuance, setTotalIssuance] = useState<string>("0");
  const [sessionIndex, setSessionIndex] = useState<number>(0);
  const [blocks, setBlocks] = useState<BlockInfo[]>([]);
  const [events, setEvents] = useState<ShieldedEvent[]>([]);

  useEffect(() => {
    if (!api || !isConnected) return;

    let unsubBlocks: (() => void) | null = null;
    let unsubEvents: (() => void) | null = null;
    const blockTimes: number[] = [];
    let lastBlockTime = Date.now();

    async function subscribe() {
      if (!api) return;

      // Subscribe to new block headers
      unsubBlocks = await api.derive.chain.subscribeNewHeads(async (header) => {
        const blockNum = header.number.toNumber();
        setLastBlock(blockNum);

        // Calculate average block time
        const now = Date.now();
        const timeDiff = (now - lastBlockTime) / 1000;
        lastBlockTime = now;
        
        if (timeDiff > 0 && timeDiff < 120) {
          blockTimes.push(timeDiff);
          if (blockTimes.length > 10) blockTimes.shift();
          const avg = blockTimes.reduce((a, b) => a + b, 0) / blockTimes.length;
          setAvgBlockTime(Math.round(avg));
        }

        // Add block to list
        setBlocks((prev) => {
          const newBlock: BlockInfo = {
            number: blockNum,
            hash: header.hash.toHex(),
            parentHash: header.parentHash.toHex(),
            timestamp: Date.now(),
            extrinsicCount: 0,
          };
          const updated = [newBlock, ...prev].slice(0, 20);
          return updated;
        });
      });

      // Subscribe to events
      const eventUnsub = await api.query.system.events((eventRecords: unknown) => {
        const shieldedEvents: ShieldedEvent[] = [];
        const records = eventRecords as { event: { section: string; method: string; data: { toJSON: () => unknown }[] } }[];
        
        records.forEach((record, idx) => {
          const { event } = record;
          if (event.section === "shieldedPool") {
            shieldedEvents.push({
              block: lastBlock,
              eventIndex: idx,
              method: event.method,
              data: event.data.map((d) => d.toJSON()) as unknown as Record<string, unknown>,
            });
          }
        });

        if (shieldedEvents.length > 0) {
          setEvents((prev) => [...shieldedEvents, ...prev].slice(0, 50));
        }
      });
      unsubEvents = eventUnsub as unknown as () => void;

      // Get session index
      try {
        const session = await api.query.session?.currentIndex?.() as { toNumber?: () => number } | undefined;
        if (session?.toNumber) {
          setSessionIndex(session.toNumber());
        }
      } catch {
        // Session pallet may not exist
      }
    }

    subscribe();

    // Poll total issuance
    const issuanceInterval = setInterval(async () => {
      if (!api) return;
      try {
        const issuance = await api.query.balances.totalIssuance();
        const formatted = (BigInt(issuance.toString()) / BigInt(10 ** 12)).toString();
        setTotalIssuance(formatted);
      } catch {
        // Ignore errors
      }
    }, 5000);

    return () => {
      if (unsubBlocks) unsubBlocks();
      if (unsubEvents) unsubEvents();
      clearInterval(issuanceInterval);
    };
  }, [api, isConnected, lastBlock]);

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
          label="Total Issuance"
          value={`${totalIssuance} HGM`}
          icon={Coins}
        />
        <StatCard
          label="Session"
          value={`#${sessionIndex}`}
          icon={Hash}
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
