import type { ReactNode } from "react";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800">
        <div className="mx-auto flex max-w-5xl items-center gap-3 px-6 py-4">
          <img src="/favicon.svg" alt="" className="h-8 w-8" />
          <span className="text-lg font-semibold tracking-tight">CipherForge</span>
          <span className="text-sm text-slate-400">Security operations console</span>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-6 py-8">{children}</main>
    </div>
  );
}
