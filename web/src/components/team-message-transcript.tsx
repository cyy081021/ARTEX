"use client";

import * as React from "react";
import { Transcript } from "@/components/transcript";
import { Badge } from "@/components/ui/badge";
import type { Activity, TeamSessionMessage } from "@/lib/types";

// The shared transport already contains the complete, message-only projection.
// Reuse the ordinary transcript without requesting the owner's raw activity API.
export function TeamMessageTranscript({ messages }: { messages: TeamSessionMessage[] }) {
  const bodies = React.useMemo(() => new Map(messages.map((message) => [message.id, message.text])), [messages]);
  const fetchDetail = React.useCallback(async (id: number) => bodies.get(id) ?? "", [bodies]);
  return (
    <div className="flex flex-col gap-1">
      {messages.map((message) => {
        const activity: Activity = {
          seq: message.id,
          kind: message.kind === "user" ? "user" : "result",
          worker: "shared",
          ts: message.created_at,
          summary: message.text,
          detail: message.text,
        };
        return (
          <div key={message.id} className="min-w-0">
            {(message.member_id > 0 || message.executor_id > 0 || message.guidance_status) && (
              <div className="flex flex-wrap gap-2 text-[10px] text-muted-foreground">
                {message.member_id > 0 && <span>成员 #{message.member_id}</span>}
                {message.executor_id > 0 && <span>设备 #{message.executor_id}</span>}
                {message.guidance_status && (
                  <Badge variant="outline" className="h-4 px-1 text-[9px]">
                    {message.guidance_status === "pending"
                      ? "待交付"
                      : message.guidance_status === "delivered"
                        ? "已交付执行边界"
                        : "本轮结束，未交付"}
                  </Badge>
                )}
              </div>
            )}
            <Transcript activity={[activity]} fetchDetail={fetchDetail} />
          </div>
        );
      })}
    </div>
  );
}
