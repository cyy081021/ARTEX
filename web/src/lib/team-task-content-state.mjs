export function acceptsTeamTaskResponse(requestScope, currentScope, requestID, currentRequestID) {
  return requestScope === currentScope && requestID === currentRequestID;
}

export function matchesTeamTaskScope(dataScope, currentScope) {
  return dataScope !== "" && dataScope === currentScope;
}
