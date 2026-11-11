import type { ReactNode } from "react";

interface CardProps {
  title: string;
  /** Heading level. Cards inside a section that already has an h2 use h3. */
  as?: "h2" | "h3";
  badge?: ReactNode;
  children: ReactNode;
}

export default function Card({ title, as: Heading = "h2", badge, children }: CardProps) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-start justify-between gap-4">
        <Heading className="text-base font-semibold">{title}</Heading>
        {badge}
      </div>
      <div className="mt-3 text-sm text-slate-300">{children}</div>
    </section>
  );
}
