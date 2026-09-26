// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// YOURS TO WRITE. This file ships as a stub.
//
// Put here the rules more than one route needs, so "what ends a session" has exactly
// one implementation. Sources: PERMISSIONS.md §7.2 and D8.
//
// Two traps worth naming before you start:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them is
//     the modelling error the auditor role exists to catch.
//   - a permission change does NOT end a session in flight (grantfathering). Suspension,
//     membership removal and device transfer DO. See PERMISSIONS.md §7.

import { badRequest, forbidden, lastOwner } from './http.js';
import { nowIso } from './db.js';
import { resolve } from './permissions.js';

export function roleRanks(db) {
  return Object.fromEntries(db.prepare('SELECT key,rank FROM roles').all().map((row) => [row.key, row.rank]));
}
export function assertRoleExists(db, role) {
  if (!db.prepare('SELECT 1 FROM roles WHERE key=?').get(role)) throw badRequest('unknown role');
}
export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  const ownersManagingOwners = callerRole === 'owner' && targetRole === 'owner';
  if (ranks[callerRole] === undefined || ranks[targetRole] === undefined || (!ownersManagingOwners && ranks[callerRole] <= ranks[targetRole]))
    throw forbidden('cannot modify a member at this role', 'role_hierarchy');
}
export function assertNotLastOwner(db, orgId, userId) {
  const target = db.prepare("SELECT role,status FROM memberships WHERE org_id=? AND user_id=?").get(orgId, userId);
  if (target?.role === 'owner' && target.status === 'active') {
    const count = db.prepare("SELECT count(*) AS n FROM memberships WHERE org_id=? AND role='owner' AND status='active'").get(orgId).n;
    if (count <= 1) throw lastOwner();
  }
}
export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  const clauses = ["state='active'", 'org_id=?'];
  const args = [orgId];
  if (userId) { clauses.push('user_id=?'); args.push(userId); }
  if (deviceId) { clauses.push('device_id=?'); args.push(deviceId); }
  if (exceptSessionId) { clauses.push('id<>?'); args.push(exceptSessionId); }
  return db.prepare(`UPDATE sessions SET state='ended',end_reason=?,ended_at=? WHERE ${clauses.join(' AND ')}`).run(reason, nowIso(), ...args);
}
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  return JSON.stringify(resolve(db, { userId, orgId, deviceId }));
}
export function sessionExpiry(db, orgId) {
  const row = db.prepare('SELECT max_session_minutes FROM organizations WHERE id=?').get(orgId);
  return new Date(Date.now() + (row?.max_session_minutes ?? 60) * 60_000).toISOString();
}
