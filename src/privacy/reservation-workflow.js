import {
  reservationHeartbeatIntervalMs,
  reservationStatuses
} from "./reservation.js";

const reservationIDs = batch => [...(batch?.reservation_ids || [])].filter(Boolean).map(String);
const leaseToken = batch => batch?.lease_token || batch?.reservations?.[0]?.lease_token || "";

export function appendReservationCleanupErrors(error, cleanupErrors = []) {
  if (!cleanupErrors.length || !error || typeof error !== "object") return;
  try {
    error.reservationCleanupErrors = [
      ...(Array.isArray(error.reservationCleanupErrors) ? error.reservationCleanupErrors : []),
      ...cleanupErrors
    ];
  } catch {
    // Cleanup annotations are best-effort and must not replace the original error.
  }
}

export async function reservationAvailableNotes(reservationManager, notes) {
  if (!reservationManager) return notes;
  if (typeof reservationManager.filterAvailableNotes !== "function") {
    throw new Error("reservationManager.filterAvailableNotes is required");
  }
  return reservationManager.filterAvailableNotes(notes);
}

export function reservationBatchSummary(batch) {
  if (!batch) return null;
  return {
    operation_id: batch.operation_id,
    lease_owner: batch.lease_owner || batch.reservations?.[0]?.lease_owner || "",
    lease_token: leaseToken(batch),
    lease_until: batch.lease_until || batch.reservations?.[0]?.lease_until || "",
    reservation_ids: [...(batch.reservation_ids || [])],
    reservations: [...(batch.reservations || [])]
  };
}

export async function markReservationProofReady(reservationManager, batch, metadata) {
  if (!reservationManager || !batch?.reservation_ids?.length) return [];
  if (typeof reservationManager.markProofReady !== "function") {
    throw new Error("reservationManager.markProofReady is required");
  }
  const reservations = await reservationManager.markProofReady(batch.reservation_ids, {
    ...metadata,
    leaseToken: leaseToken(batch)
  });
  batch.reservations = reservations;
  batch.lease_until = reservations[0]?.lease_until || batch.lease_until;
  return reservations;
}

export async function renewReservationLease(reservationManager, batch) {
  if (!reservationManager || !batch?.reservation_ids?.length ||
      typeof reservationManager.renewLease !== "function") return [];
  const reservations = await reservationManager.renewLease(batch.reservation_ids, {
    leaseToken: leaseToken(batch)
  });
  batch.reservations = reservations;
  batch.lease_until = reservations[0]?.lease_until || batch.lease_until;
  return reservations;
}

async function reachedBroadcastTerminal(reservationManager, batch) {
  const ids = reservationIDs(batch);
  if (!ids.length || typeof reservationManager?.getReservation !== "function") return false;
  try {
    const records = await Promise.all(ids.map(id => reservationManager.getReservation(id)));
    return records.length === ids.length && records.every(record =>
      record?.status === reservationStatuses.Submitted ||
      record?.status === reservationStatuses.Unknown
    );
  } catch {
    return false;
  }
}

export async function withReservationHeartbeat(reservationManager, batch, task, {
  acceptBroadcastTerminal = false,
  phase = "proof generation"
} = {}) {
  if (!reservationManager || !batch?.reservation_ids?.length ||
      typeof reservationManager.renewLease !== "function") {
    return task({ assertHeartbeatHealthy() {}, async heartbeatNow() {} });
  }

  await renewReservationLease(reservationManager, batch);
  const intervalMs = reservationHeartbeatIntervalMs({
    leaseDurationMs: reservationManager.leaseDurationMs,
    leaseUntil: batch.lease_until || batch.reservations?.[0]?.lease_until
  });
  let heartbeatError = null;
  let inFlight = null;

  const assertHeartbeatHealthy = () => {
    if (!heartbeatError) return;
    const error = new Error(`note reservation lease heartbeat failed during ${phase}`);
    error.name = "ReservationHeartbeatError";
    error.cause = heartbeatError;
    throw error;
  };
  const heartbeat = async () => {
    if (heartbeatError) return;
    try {
      await renewReservationLease(reservationManager, batch);
    } catch (error) {
      heartbeatError = error;
    }
  };
  const heartbeatNow = async () => {
    inFlight ||= heartbeat().finally(() => { inFlight = null; });
    await inFlight;
    assertHeartbeatHealthy();
  };
  const timer = typeof globalThis.setInterval === "function"
    ? globalThis.setInterval(() => { void heartbeatNow().catch(() => {}); }, intervalMs)
    : null;

  let result;
  let completed = false;
  try {
    result = await task({ assertHeartbeatHealthy, heartbeatNow });
    completed = true;
  } finally {
    if (timer && typeof globalThis.clearInterval === "function") globalThis.clearInterval(timer);
    if (inFlight) await inFlight;
  }
  if (!completed || !heartbeatError) return result;
  if (acceptBroadcastTerminal && await reachedBroadcastTerminal(reservationManager, batch)) return result;
  return {
    ...result,
    reservationReconciliationRequired: true,
    reservationReconciliationWarning: {
      code: "reservation_heartbeat_failed_after_proof_ready",
      message: "The prepared artifact is durable, but reservation reconciliation is required before broadcast.",
      cause: heartbeatError?.message || String(heartbeatError)
    }
  };
}

export function reservationReconciliationFields(result = {}) {
  return result.reservationReconciliationRequired === true
    ? {
        reservationReconciliationRequired: true,
        reservationReconciliationWarning: result.reservationReconciliationWarning
      }
    : {};
}
