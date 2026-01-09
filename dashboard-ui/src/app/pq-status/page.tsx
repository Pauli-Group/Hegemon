"use client";

import { useEffect, useState } from "react";
import { useApi } from "@/providers/ApiProvider";
import { StatCard } from "@/components/StatCard";
import { KeyRound, Shield, Lock, Fingerprint, CheckCircle } from "lucide-react";

interface StarkParams {
  hash: string;
  friQueries: number;
  blowupFactor: number;
  securityBits: number;
}

export default function PQStatusPage() {
  const { api, isConnected, isConnecting, error } = useApi();
  const [starkParams, setStarkParams] = useState<StarkParams | null>(null);

  useEffect(() => {
    if (!api || !isConnected) return;

    async function fetchPQStatus() {
      if (!api) return;

      try {
        // Try to get STARK verifier params from shielded pool
        if (api.query.shieldedPool?.verifyingKeyParamsStorage) {
          const params = await api.query.shieldedPool.verifyingKeyParamsStorage();
          if (params && !params.isEmpty) {
            const paramsJson = params.toJSON() as {
              hash?: string;
              fri_queries?: number;
              blowup_factor?: number;
              security_bits?: number;
            };
            setStarkParams({
              hash: paramsJson.hash || "Blake3",
              friQueries: paramsJson.fri_queries || 0,
              blowupFactor: paramsJson.blowup_factor || 0,
              securityBits: paramsJson.security_bits || 0,
            });
          }
        }
      } catch (err) {
        console.error("Failed to fetch PQ status:", err);
      }
    }

    fetchPQStatus();
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
      <div className="flex items-center gap-3 mb-8">
        <div className="w-10 h-10 rounded-lg bg-ionosphere/10 flex items-center justify-center">
          <KeyRound size={24} className="text-ionosphere" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold text-neutral-light">Post-Quantum Cryptography</h1>
          <p className="text-neutral-mid text-sm">Quantum-resistant cryptographic primitives status</p>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Signature Scheme"
          value="ML-DSA-65"
          icon={Fingerprint}
        />
        <StatCard
          label="KEM Scheme"
          value="ML-KEM-768"
          icon={Lock}
        />
        <StatCard
          label="Proof System"
          value="STARK"
          icon={Shield}
        />
        <StatCard
          label="PQ Status"
          value="Active"
          icon={CheckCircle}
        />
      </div>

      {/* Cryptographic Primitives */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
        <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-neutral-light mb-4 flex items-center gap-2">
            <Fingerprint size={20} className="text-ionosphere" />
            Digital Signatures
          </h3>
          <div className="space-y-3">
            <div className="flex justify-between py-2 border-b border-neutral-mid/10">
              <span className="text-neutral-mid">Primary Scheme</span>
              <span className="text-ionosphere font-mono">ML-DSA-65</span>
            </div>
            <div className="flex justify-between py-2 border-b border-neutral-mid/10">
              <span className="text-neutral-mid">Standard</span>
              <span className="text-neutral-light font-mono">FIPS 204</span>
            </div>
            <div className="flex justify-between py-2 border-b border-neutral-mid/10">
              <span className="text-neutral-mid">Security Level</span>
              <span className="text-neutral-light font-mono">NIST Level 3</span>
            </div>
            <div className="flex justify-between py-2 border-b border-neutral-mid/10">
              <span className="text-neutral-mid">Public Key Size</span>
              <span className="text-neutral-light font-mono">1,952 bytes</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-neutral-mid">Signature Size</span>
              <span className="text-neutral-light font-mono">3,293 bytes</span>
            </div>
          </div>
        </div>

        <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-neutral-light mb-4 flex items-center gap-2">
            <Lock size={20} className="text-ionosphere" />
            Key Encapsulation
          </h3>
          <div className="space-y-3">
            <div className="flex justify-between py-2 border-b border-neutral-mid/10">
              <span className="text-neutral-mid">KEM Scheme</span>
              <span className="text-ionosphere font-mono">ML-KEM-768</span>
            </div>
            <div className="flex justify-between py-2 border-b border-neutral-mid/10">
              <span className="text-neutral-mid">Standard</span>
              <span className="text-neutral-light font-mono">FIPS 203</span>
            </div>
            <div className="flex justify-between py-2 border-b border-neutral-mid/10">
              <span className="text-neutral-mid">Security Level</span>
              <span className="text-neutral-light font-mono">NIST Level 3</span>
            </div>
            <div className="flex justify-between py-2 border-b border-neutral-mid/10">
              <span className="text-neutral-mid">Public Key Size</span>
              <span className="text-neutral-light font-mono">1,184 bytes</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-neutral-mid">Ciphertext Size</span>
              <span className="text-neutral-light font-mono">1,088 bytes</span>
            </div>
          </div>
        </div>
      </div>

      {/* STARK Verifier */}
      <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6 mb-8">
        <h3 className="text-lg font-semibold text-neutral-light mb-4 flex items-center gap-2">
          <Shield size={20} className="text-ionosphere" />
          STARK Proof System
        </h3>
        <p className="text-neutral-mid text-sm mb-4">
          Transparent zero-knowledge proofs with no trusted setup, using only collision-resistant hash functions.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-midnight/50 border border-neutral-mid/10 rounded-lg p-4 text-center">
            <p className="text-neutral-mid text-xs uppercase tracking-wider mb-1">Hash Function</p>
            <p className="text-ionosphere font-mono text-lg">
              {starkParams?.hash || "Blake3"}
            </p>
          </div>
          <div className="bg-midnight/50 border border-neutral-mid/10 rounded-lg p-4 text-center">
            <p className="text-neutral-mid text-xs uppercase tracking-wider mb-1">FRI Queries</p>
            <p className="text-ionosphere font-mono text-lg">
              {starkParams?.friQueries || "—"}
            </p>
          </div>
          <div className="bg-midnight/50 border border-neutral-mid/10 rounded-lg p-4 text-center">
            <p className="text-neutral-mid text-xs uppercase tracking-wider mb-1">Blowup Factor</p>
            <p className="text-ionosphere font-mono text-lg">
              {starkParams?.blowupFactor || "—"}
            </p>
          </div>
          <div className="bg-midnight/50 border border-neutral-mid/10 rounded-lg p-4 text-center">
            <p className="text-neutral-mid text-xs uppercase tracking-wider mb-1">Security Bits</p>
            <p className="text-ionosphere font-mono text-lg">
              {starkParams?.securityBits || "128"}
            </p>
          </div>
        </div>
      </div>

      {/* Security Comparison */}
      <div className="bg-midnight border border-neutral-mid/20 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-neutral-light mb-4">Quantum Security Comparison</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-neutral-mid/20">
                <th className="text-left py-3 px-4 text-neutral-mid font-medium">Primitive</th>
                <th className="text-left py-3 px-4 text-neutral-mid font-medium">Hegemon (PQ)</th>
                <th className="text-left py-3 px-4 text-neutral-mid font-medium">Zcash (Classical)</th>
                <th className="text-left py-3 px-4 text-neutral-mid font-medium">Quantum Safe</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-neutral-mid/10">
                <td className="py-3 px-4 text-neutral-light">Signatures</td>
                <td className="py-3 px-4 font-mono text-ionosphere">ML-DSA</td>
                <td className="py-3 px-4 font-mono text-neutral-mid">Ed25519</td>
                <td className="py-3 px-4"><span className="text-proof-green">✓ Yes</span></td>
              </tr>
              <tr className="border-b border-neutral-mid/10">
                <td className="py-3 px-4 text-neutral-light">Key Exchange</td>
                <td className="py-3 px-4 font-mono text-ionosphere">ML-KEM</td>
                <td className="py-3 px-4 font-mono text-neutral-mid">X25519</td>
                <td className="py-3 px-4"><span className="text-proof-green">✓ Yes</span></td>
              </tr>
              <tr className="border-b border-neutral-mid/10">
                <td className="py-3 px-4 text-neutral-light">ZK Proofs</td>
                <td className="py-3 px-4 font-mono text-ionosphere">STARK</td>
                <td className="py-3 px-4 font-mono text-neutral-mid">Groth16</td>
                <td className="py-3 px-4"><span className="text-proof-green">✓ Yes</span></td>
              </tr>
              <tr>
                <td className="py-3 px-4 text-neutral-light">Trusted Setup</td>
                <td className="py-3 px-4 font-mono text-ionosphere">None</td>
                <td className="py-3 px-4 font-mono text-neutral-mid">Required</td>
                <td className="py-3 px-4"><span className="text-proof-green">✓ N/A</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
