"use client";

import * as React from "react";
import { useSearchParams } from "next/navigation";
import { FindingDetailContent } from "./finding-detail-content";

function FindingDetailRoute() {
  const searchParams = useSearchParams();
  return (
    <FindingDetailContent
      findingId={searchParams.get("id") ?? ""}
      contextTaskId={searchParams.get("context_task") ?? undefined}
    />
  );
}

export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <FindingDetailRoute />
    </React.Suspense>
  );
}
