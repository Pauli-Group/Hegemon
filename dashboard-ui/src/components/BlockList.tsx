import type { BlockInfo } from "@/lib/types";
import { Blocks } from "lucide-react";

interface BlockListProps {
  blocks: BlockInfo[];
}

export function BlockList({ blocks }: BlockListProps) {
  if (blocks.length === 0) {
    return (
      <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-neutral-light mb-4 flex items-center gap-2">
          <Blocks size={20} className="text-ionosphere" />
          Recent Blocks
        </h2>
        <div className="text-center py-8">
          <div className="w-6 h-6 border-2 border-neutral-mid/50 border-t-ionosphere rounded-full animate-spin mx-auto mb-3" />
          <p className="text-neutral-mid text-sm">Waiting for blocks...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
      <h2 className="text-lg font-semibold text-neutral-light mb-4 flex items-center gap-2">
        <Blocks size={20} className="text-ionosphere" />
        Recent Blocks
      </h2>
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {blocks.map((block) => (
          <div
            key={block.hash}
            className="flex items-center justify-between py-3 px-3 rounded-lg hover:bg-ionosphere/5 transition-colors duration-150 border border-transparent hover:border-ionosphere/20"
          >
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded bg-ionosphere/10 flex items-center justify-center">
                <span className="text-ionosphere text-xs font-mono">
                  {block.number % 1000}
                </span>
              </div>
              <div>
                <p className="text-neutral-light font-medium">
                  Block #{block.number.toLocaleString()}
                </p>
                <p className="text-neutral-mid text-xs font-mono">
                  {block.hash.slice(0, 10)}...{block.hash.slice(-8)}
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-neutral-mid text-xs">
                {formatTimeAgo(block.timestamp)}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}
