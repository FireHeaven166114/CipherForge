import type { ReactNode } from "react";

import Panel from "./hud/Panel";

interface CardProps {
  title: string;
  /** Heading level. Cards inside a section that already has an h2 use h3. */
  as?: "h2" | "h3";
  /** A short tag printed before the title, such as "ASM". Decorative. */
  code?: string;
  badge?: ReactNode;
  children: ReactNode;
}

/** A titled HUD panel with the standard body padding. */
export default function Card({ title, as, code, badge, children }: CardProps) {
  return (
    <Panel title={title} as={as} code={code} actions={badge}>
      {children}
    </Panel>
  );
}
