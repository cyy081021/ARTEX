"use client";

import { TabsContent } from "@/components/ui/tabs";
import { AssetsTab } from "./_tabs/assets-tab";
import { BroadcastTab } from "./_tabs/broadcast-tab";
import { CoverageGraphTab } from "./_tabs/coverage-graph-tab";
import { FindingsTab } from "./_tabs/findings-tab";
import { FindingRelationsTab } from "./_tabs/finding-relations-tab";
import { GraphTab } from "./_tabs/graph-tab";
import { InterceptTab } from "./_tabs/intercept-tab";
import { OverviewTab } from "./_tabs/overview-tab";
import { ReportTab } from "./_tabs/report-tab";
import { RetestsTab } from "./_tabs/retests-tab";
import { ReverseTab } from "./_tabs/reverse-tab";
import { WorkflowRequestsTab } from "./_tabs/workflow-requests-tab";

export function TaskDetailViews({ taskId, kind, paused, coverageEnabled = true, onStart = () => {} }: {
  taskId: string; kind?: string; paused: boolean; coverageEnabled?: boolean; onStart?: () => void;
}) {
  return <>
    <TabsContent value="overview" className="mt-0"><OverviewTab taskId={taskId} /></TabsContent>
    <TabsContent value="graph" className="mt-0"><GraphTab taskId={taskId} /></TabsContent>
    <TabsContent value="broadcast" className="mt-0"><BroadcastTab taskId={taskId} /></TabsContent>
    <TabsContent value="workflow-requests" className="mt-0"><WorkflowRequestsTab taskId={taskId} taskKind={kind === "reverse" ? "reverse" : "pentest"} /></TabsContent>
    {kind === "reverse" ? <TabsContent value="reverse" className="mt-0"><ReverseTab taskId={taskId} paused={paused} onStart={onStart} /></TabsContent> : <>
      <TabsContent value="findings" className="mt-0"><FindingsTab taskId={taskId} /></TabsContent>
      <TabsContent value="finding-relations" className="mt-0"><FindingRelationsTab taskId={taskId} /></TabsContent>
      <TabsContent value="retests" className="mt-0"><RetestsTab key={taskId} taskId={taskId} /></TabsContent>
      <TabsContent value="assets" className="mt-0"><AssetsTab taskId={taskId} /></TabsContent>
      <TabsContent value="coverage" className="mt-0"><CoverageGraphTab taskId={taskId} coverageEnabled={coverageEnabled} /></TabsContent>
      <TabsContent value="intercept" className="mt-0"><InterceptTab taskId={taskId} /></TabsContent>
      <TabsContent value="report" className="mt-0"><ReportTab taskId={taskId} /></TabsContent>
    </>}
  </>;
}
