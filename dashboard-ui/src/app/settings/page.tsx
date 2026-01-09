"use client";

import { useState } from "react";
import { useApi } from "@/providers/ApiProvider";
import { Settings, Server, RefreshCw } from "lucide-react";

export default function SettingsPage() {
  const { endpoint, isConnected, error } = useApi();
  const [customEndpoint, setCustomEndpoint] = useState(endpoint);

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="flex items-center gap-3 mb-8">
        <div className="w-10 h-10 rounded-lg bg-ionosphere/10 flex items-center justify-center">
          <Settings size={24} className="text-ionosphere" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold text-neutral-light">Settings</h1>
          <p className="text-neutral-mid text-sm">Configure dashboard connection and preferences</p>
        </div>
      </div>

      {/* Connection Settings */}
      <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6 mb-8">
        <h2 className="text-lg font-semibold text-neutral-light mb-4 flex items-center gap-2">
          <Server size={20} className="text-ionosphere" />
          Node Connection
        </h2>
        
        <div className="space-y-4">
          <div>
            <label className="block text-neutral-mid text-sm mb-2">WebSocket Endpoint</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={customEndpoint}
                onChange={(e) => setCustomEndpoint(e.target.value)}
                className="flex-1 bg-midnight border border-neutral-mid/30 rounded-lg px-4 py-2 text-neutral-light font-mono text-sm focus:border-ionosphere focus:outline-none"
                placeholder="ws://127.0.0.1:9944"
              />
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 bg-ionosphere/10 text-ionosphere rounded-lg hover:bg-ionosphere/20 transition-colors flex items-center gap-2"
              >
                <RefreshCw size={16} />
                Reconnect
              </button>
            </div>
          </div>

          <div className="flex items-center gap-4 pt-4 border-t border-neutral-mid/10">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${isConnected ? "bg-proof-green" : "bg-guard-rail"}`} />
              <span className="text-sm text-neutral-mid">
                {isConnected ? "Connected" : "Disconnected"}
              </span>
            </div>
            {error && (
              <span className="text-sm text-guard-rail">{error}</span>
            )}
          </div>
        </div>
      </div>

      {/* Quick Connect */}
      <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6 mb-8">
        <h2 className="text-lg font-semibold text-neutral-light mb-4">Quick Connect</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            onClick={() => setCustomEndpoint("ws://127.0.0.1:9944")}
            className="p-4 border border-neutral-mid/20 rounded-lg hover:border-ionosphere/50 transition-colors text-left"
          >
            <p className="text-neutral-light font-medium">Local Dev Node</p>
            <p className="text-neutral-mid text-sm font-mono">ws://127.0.0.1:9944</p>
          </button>
          <button
            onClick={() => setCustomEndpoint("wss://testnet.hegemon.network")}
            className="p-4 border border-neutral-mid/20 rounded-lg hover:border-ionosphere/50 transition-colors text-left"
          >
            <p className="text-neutral-light font-medium">Testnet</p>
            <p className="text-neutral-mid text-sm font-mono">wss://testnet.hegemon.network</p>
          </button>
          <button
            onClick={() => setCustomEndpoint("wss://rpc.hegemon.network")}
            className="p-4 border border-neutral-mid/20 rounded-lg hover:border-ionosphere/50 transition-colors text-left"
          >
            <p className="text-neutral-light font-medium">Mainnet</p>
            <p className="text-neutral-mid text-sm font-mono">wss://rpc.hegemon.network</p>
          </button>
        </div>
      </div>

      {/* About */}
      <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-neutral-light mb-4">About Hegemon Explorer</h2>
        <div className="space-y-2 text-sm text-neutral-mid">
          <p>A privacy-focused blockchain explorer for the Hegemon network.</p>
          <p>Built with Next.js and @polkadot/api.</p>
          <div className="pt-4 border-t border-neutral-mid/10 mt-4">
            <p className="font-mono text-xs">Version: 0.1.0</p>
          </div>
        </div>
      </div>
    </div>
  );
}
