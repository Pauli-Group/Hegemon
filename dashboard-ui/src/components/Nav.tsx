"use client";

import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";
import { 
  Blocks, 
  Pickaxe, 
  Shield,
  Settings 
} from "lucide-react";
import { clsx } from "clsx";

const navItems = [
  { href: "/", label: "Explorer", icon: Blocks },
  { href: "/mining", label: "Mining", icon: Pickaxe },
  { href: "/shielded", label: "Shielded Pool", icon: Shield },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Nav() {
  const pathname = usePathname();

  return (
    <nav className="fixed top-0 left-0 right-0 h-16 bg-midnight border-b border-neutral-mid/20 z-50">
      <div className="max-w-7xl mx-auto px-4 h-full flex items-center justify-between">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2">
          <Image 
            src="/hegemon-atlas-emblem.svg" 
            alt="Hegemon" 
            width={32} 
            height={32}
            className="h-8 w-8"
          />
          <span className="text-xl font-semibold text-neutral-light">
            Hegemon
          </span>
        </Link>

        {/* Navigation Links */}
        <div className="flex items-center gap-1">
          {navItems.map(({ href, label, icon: Icon }) => {
            const isActive = pathname === href;
            return (
              <Link
                key={href}
                href={href}
                className={clsx(
                  "flex items-center gap-2 px-4 py-2 rounded-lg transition-colors duration-150",
                  isActive
                    ? "bg-ionosphere/10 text-ionosphere"
                    : "text-neutral-mid hover:text-ionosphere hover:bg-ionosphere/5"
                )}
              >
                <Icon size={18} strokeWidth={1.5} />
                <span className="text-sm font-medium">{label}</span>
              </Link>
            );
          })}
        </div>

        {/* Connection Status */}
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-proof-green animate-pulse" />
          <span className="text-sm text-neutral-mid">Connected</span>
        </div>
      </div>
    </nav>
  );
}
