import type { ReactNode } from "react";

import { Card, CardContent } from "@/components/ui/card";
import { type T7StatusSnapshot, t7StatusContent } from "@/lib/status";

function OfflineStatusCard({
  title, children, initiallyOpen = false,
}: {
  title: string;
  children: ReactNode;
  initiallyOpen?: boolean;
}) {
  return (
    <Card className="min-w-0" size="sm">
      <CardContent>
        <details open={initiallyOpen}>
          <summary className="cursor-pointer rounded-sm text-sm font-medium focus-visible:outline-2 focus-visible:outline-ring">
            <h2 className="inline">{title} <span className="text-xs font-normal text-muted-foreground">（离线示例）</span></h2>
          </summary>
          {children}
        </details>
      </CardContent>
    </Card>
  );
}

export function T7StatusCard({ snapshot }: { snapshot: T7StatusSnapshot }) {
  const content = t7StatusContent(snapshot);
  return (
    <OfflineStatusCard title="T7 状态快照" initiallyOpen>
      {typeof content === "string" ? (
        <p role="status" className="mt-3 text-sm text-muted-foreground">{content}</p>
      ) : (
        <dl className="mt-3 grid grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-2 lg:grid-cols-3">
          {content.map(([label, value]) => (
            <div key={label} className="min-w-0">
              <dt className="text-xs text-muted-foreground">{label}</dt>
              <dd className="break-words text-sm font-medium tabular-nums">{value}</dd>
            </div>
          ))}
        </dl>
      )}
    </OfflineStatusCard>
  );
}

export function SoftwareReviewHistory({ history }: { history?: readonly { reason: string }[] }) {
  if (!history?.length) return null;
  return (
    <OfflineStatusCard title="软件工作单 · 派工与复核记录">
      <ol className="mt-3 grid list-decimal gap-1 pl-5 text-sm">
        {history.map(({ reason }, index) => (
          <li className="break-words" key={index}>{reason}</li>
        ))}
      </ol>
    </OfflineStatusCard>
  );
}
