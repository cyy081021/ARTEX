import type { T7StatusSnapshot } from "./status";

type ReviewHistory = readonly { readonly reason: string }[];

type Selection = Readonly<{ recordId: string }>;

type OfflineView = Readonly<{
  pending: Selection | null;
  snapshot: T7StatusSnapshot;
  history?: ReviewHistory;
}>;

// Begin a new display lifetime on every selection or visibility change, even for the same ID.
export function selectOfflineRecord(recordId: string | null, visible: boolean): OfflineView {
  if (!recordId) return { pending: null, snapshot: { kind: "unselected" } };
  if (visible !== true) return { pending: null, snapshot: { kind: "forbidden" } };
  return { pending: { recordId }, snapshot: { kind: "loading" } };
}

// An injected sample belongs to the selection captured when it was requested for display.
// Compare against the current view, and consume the selection on its first terminal result.
export function applyOfflineSnapshot(
  current: OfflineView,
  selection: Selection | null,
  snapshot: T7StatusSnapshot,
  history?: ReviewHistory,
): OfflineView {
  if (!selection || selection !== current.pending || snapshot.kind === "loading") return current;
  if (snapshot.kind !== "ready") return { pending: null, snapshot: { kind: snapshot.kind } };
  const displayHistory = Array.isArray(history)
    ? history.map((entry) => {
        const reason: unknown = entry?.reason;
        return { reason: typeof reason === "string" && reason.trim() !== "" ? reason : "未提供原因" };
      })
    : undefined;
  return { pending: null, snapshot, history: displayHistory };
}
