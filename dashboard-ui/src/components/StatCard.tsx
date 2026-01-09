import { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: string;
  icon: LucideIcon;
  trend?: "up" | "down" | "neutral";
}

export function StatCard({ label, value, icon: Icon, trend }: StatCardProps) {
  return (
    <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-4 hover:border-ionosphere/30 transition-colors duration-150">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-neutral-mid text-xs uppercase tracking-wider mb-1">
            {label}
          </p>
          <p className="text-neutral-light text-xl font-semibold font-mono">
            {value}
          </p>
        </div>
        <div className="w-10 h-10 rounded-lg bg-ionosphere/10 flex items-center justify-center">
          <Icon size={20} className="text-ionosphere" strokeWidth={1.5} />
        </div>
      </div>
      {trend && (
        <div className="mt-2">
          <span
            className={`text-xs ${
              trend === "up"
                ? "text-proof-green"
                : trend === "down"
                ? "text-guard-rail"
                : "text-neutral-mid"
            }`}
          >
            {trend === "up" ? "↑" : trend === "down" ? "↓" : "→"}
          </span>
        </div>
      )}
    </div>
  );
}
