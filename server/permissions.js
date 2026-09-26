// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const catalogue = db.prepare('SELECT key FROM permissions').all().map((row) => row.key);
  const membership = db.prepare('SELECT role,status FROM memberships WHERE user_id=? AND org_id=?').get(userId, orgId);
  const reason = !membership ? 'not_a_member' : membership.status !== 'active' ? membership.status : null;
  const permissions = Object.fromEntries(catalogue.map((key) => [key, { effect: 'deny', source: null, reason: reason ?? 'implicit' }]));
  if (reason) return { role: membership?.role ?? null, permissions };
  for (const row of db.prepare('SELECT permission FROM role_permissions WHERE role=?').all(membership.role)) {
    if (permissions[row.permission]) permissions[row.permission] = { effect: 'allow', source: `role:${membership.role}`, reason: null };
  }
  const instant = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
  const grants = db.prepare(`SELECT g.id,g.effect,g.device_id,gp.permission FROM grants g
    JOIN grant_permissions gp ON gp.grant_id=g.id
    WHERE g.user_id=? AND g.org_id=? AND g.revoked_at IS NULL
      AND (g.starts_at IS NULL OR g.starts_at<=?) AND (g.expires_at IS NULL OR g.expires_at>?)
      AND (g.device_id IS NULL OR ? IS NULL OR g.device_id=?)`).all(userId, orgId, instant, instant, deviceId, deviceId);
  const matches = (pattern, permission) => pattern === '*' || pattern === permission ||
    (pattern.endsWith(':*') && permission.startsWith(pattern.slice(0, -1)));
  for (const permission of catalogue) {
    const applicable = grants.filter((grant) => matches(grant.permission, permission));
    const denied = applicable.find((grant) => grant.effect === 'deny');
    const allowed = applicable.find((grant) => grant.effect === 'allow');
    if (denied) permissions[permission] = { effect: 'deny', source: `grant:${denied.id}`, reason: 'explicit_deny' };
    else if (allowed) permissions[permission] = { effect: 'allow', source: `grant:${allowed.id}`, reason: null };
  }
  return { role: membership.role, permissions };
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const byDevice = Object.fromEntries(deviceIds.map((id) => [id, resolve(db, { userId, orgId, deviceId: id, now }).permissions]));
  return { role: resolve(db, { userId, orgId, now }).role, byDevice };
}

export function can(db, ctx, permission, deviceId) {
  return resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions[permission] ??
    { effect: 'deny', source: null, reason: 'implicit' };
}

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  const decision = can(db, ctx, permission, deviceId);
  if (decision.effect !== 'allow') throw forbidden('permission denied', decision.reason === 'explicit_deny' ? 'explicit_deny' : 'missing_permission');
  return decision;
}

// No privilege laundering: you may only grant authority you hold at that scope.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const concrete = db.prepare('SELECT key FROM permissions').all().map((row) => row.key);
  const valid = new Set(db.prepare('SELECT pattern FROM permission_patterns').all().map((row) => row.pattern));
  for (const pattern of patterns) {
    if (!valid.has(pattern)) throw badRequest('unknown permission', 'unknown_permission');
    const expanded = pattern === '*' ? concrete : pattern.endsWith(':*') ? concrete.filter((p) => p.startsWith(pattern.slice(0, -1))) : [pattern];
    for (const permission of expanded) assertCan(db, ctx, permission, deviceId);
  }
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  if (!MODE_PERMISSION[mode]) throw badRequest('invalid session mode');
  const start = can(db, ctx, 'session:start', deviceId);
  if (start.effect !== 'allow') throw forbidden('cannot start sessions', 'missing_permission');
  const device = can(db, ctx, MODE_PERMISSION[mode], deviceId);
  if (device.effect !== 'allow') throw forbidden('mode not permitted on device', 'missing_device_permission');
  return { start, device };
}
