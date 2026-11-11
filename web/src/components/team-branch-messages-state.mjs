/** @typedef {{id:number,branch_id:number,kind:string}} MessageEvent */

export function branchSnapshotRequests(base, branchID, cursor, permissions) {
  const head = `${base}?after=0&limit=1`;
  if (!permissions.includes("process") || !branchID) return { head, events: null };
  return { head, events: `${base}?after=${cursor}&limit=100&branch=${branchID}` };
}

export function projectBranchEvents(current, incoming, branchID, visibleKinds, permissions) {
  if (!permissions.includes("process")) return [];
  const merged = new Map(current.map((event) => [event.id, event]));
  for (const event of incoming) {
    if (event.branch_id === branchID && visibleKinds.has(event.kind)) merged.set(event.id, event);
  }
  return [...merged.values()].sort((a, b) => a.id - b.id);
}
