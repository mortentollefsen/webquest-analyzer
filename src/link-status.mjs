export function retryHttpLinkWithGet(status) {
  return [400, 403, 405, 501].includes(status);
}

export function classifyHttpLinkResponse(status, statusText = "", ignoredStatuses = []) {
  const reason = `HTTP ${status}${statusText ? ` ${statusText}` : ""}`;
  return {
    ignored: ignoredStatuses.includes(status),
    uncertain: status === 400,
    reason: status === 400
      ? `${reason}. Serveren avviste den automatiske forespørselen. Dette bekrefter ikke at lenken er brutt; kontroller den i nettleseren.`
      : reason,
  };
}
