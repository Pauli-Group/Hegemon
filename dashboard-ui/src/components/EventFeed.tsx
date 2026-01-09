import type { ShieldedEvent } from "@/lib/types";
import { Shield, Coins, GitBranch } from "lucide-react";

interface EventFeedProps {
  events: ShieldedEvent[];
}

const eventIcons: Record<string, typeof Shield> = {
  CoinbaseMinted: Coins,
  MerkleRootUpdated: GitBranch,
};

const eventColors: Record<string, string> = {
  CoinbaseMinted: "text-amber",
  MerkleRootUpdated: "text-proof-green",
};

export function EventFeed({ events }: EventFeedProps) {
  if (events.length === 0) {
    return (
      <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-neutral-light mb-4 flex items-center gap-2">
          <Shield size={20} className="text-ionosphere" />
          Shielded Pool Events
        </h2>
        <div className="text-center py-8">
          <div className="w-6 h-6 border-2 border-neutral-mid/50 border-t-ionosphere rounded-full animate-spin mx-auto mb-3" />
          <p className="text-neutral-mid text-sm">Waiting for events...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
      <h2 className="text-lg font-semibold text-neutral-light mb-4 flex items-center gap-2">
        <Shield size={20} className="text-ionosphere" />
        Shielded Pool Events
      </h2>
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {events.map((event, idx) => {
          const Icon = eventIcons[event.method] || Shield;
          const colorClass = eventColors[event.method] || "text-ionosphere";
          
          return (
            <div
              key={`${event.block}-${event.eventIndex}-${idx}`}
              className="flex items-center justify-between py-3 px-3 rounded-lg hover:bg-ionosphere/5 transition-colors duration-150 border border-transparent hover:border-ionosphere/20"
            >
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded flex items-center justify-center bg-midnight border border-neutral-mid/30`}>
                  <Icon size={16} className={colorClass} strokeWidth={1.5} />
                </div>
                <div>
                  <p className="text-neutral-light font-medium text-sm">
                    shieldedPool.{event.method}
                  </p>
                  <p className="text-neutral-mid text-xs">
                    Block #{event.block}
                  </p>
                </div>
              </div>
              <div className="text-right">
                <span className={`text-xs px-2 py-1 rounded ${
                  event.method === "CoinbaseMinted" 
                    ? "bg-amber/10 text-amber"
                    : "bg-proof-green/10 text-proof-green"
                }`}>
                  {event.method === "CoinbaseMinted" ? "Reward" : "Update"}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
