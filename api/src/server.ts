/**
 * The case store: an evidence chain over exhibits the Python lab produces.
 *
 * Why a server exists at all in a local tool: a finding is only worth something if the thing it
 * was computed from can still be identified later. The chain is append-only, each link hashes its
 * predecessor, so an exhibit that is edited or removed shows up as a broken chain rather than a
 * quiet difference of opinion.
 *
 * Node 24 runs this file directly; the types are erasable and there is no build step.
 */
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

const MAX_BODY = 1 << 20;
const GENESIS = "0".repeat(64);

export type Signal = { noise_ratio?: number; seam_edge?: number; chroma_step?: number; block_grid?: number };

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export function openDb(path = ":memory:"): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec(`
    create table if not exists cases (
      id text primary key,
      label text not null,
      created_at text not null
    );
    create table if not exists exhibits (
      id integer primary key autoincrement,
      case_id text not null references cases(id),
      sha256 text not null,
      note text not null default '',
      prev_hash text not null,
      chain_hash text not null,
      created_at text not null
    );
    create table if not exists runs (
      id integer primary key autoincrement,
      exhibit_id integer not null references exhibits(id),
      level text not null,
      signals text not null,
      created_at text not null
    );
    create index if not exists exhibits_case on exhibits(case_id, id);
  `);
  return db;
}

/** The link is a hash of what came before it plus this row's own content. */
export function linkHash(prev: string, sha: string, note: string): string {
  return sha256(`${prev}:${sha}:${note}`);
}

export function addExhibit(db: DatabaseSync, caseId: string, sha: string, note = ""): number {
  const row = db.prepare("select chain_hash from exhibits where case_id = ? order by id desc limit 1")
    .get(caseId) as { chain_hash: string } | undefined;
  const prev = row?.chain_hash ?? GENESIS;
  const now = new Date().toISOString();
  const info = db.prepare(
    "insert into exhibits (case_id, sha256, note, prev_hash, chain_hash, created_at) values (?, ?, ?, ?, ?, ?)",
  ).run(caseId, sha, note, prev, linkHash(prev, sha, note), now);
  return Number(info.lastInsertRowid);
}

export function verifyChain(db: DatabaseSync, caseId: string): { ok: boolean; length: number; brokenAt: number | null } {
  const rows = db.prepare("select id, sha256, note, prev_hash, chain_hash from exhibits where case_id = ? order by id")
    .all(caseId) as Array<{ id: number; sha256: string; note: string; prev_hash: string; chain_hash: string }>;
  let prev = GENESIS;
  for (const row of rows) {
    if (row.prev_hash !== prev || row.chain_hash !== linkHash(prev, row.sha256, row.note)) {
      return { ok: false, length: rows.length, brokenAt: row.id };
    }
    prev = row.chain_hash;
  }
  return { ok: true, length: rows.length, brokenAt: null };
}

function send(res: ServerResponse, code: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
  res.end(payload);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  if (size === 0) return {};
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("body must be an object");
  return parsed as Record<string, unknown>;
}

export function makeServer(db: DatabaseSync) {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";
    try {
      if (method === "GET" && path === "/health") {
        return send(res, 200, { ok: true, exhibits: (db.prepare("select count(*) as n from exhibits").get() as { n: number }).n });
      }

      if (method === "POST" && path === "/cases") {
        const body = await readJson(req);
        const id = typeof body.id === "string" && body.id.trim() ? body.id.trim() : sha256(String(Date.now())).slice(0, 12);
        db.prepare("insert or ignore into cases (id, label, created_at) values (?, ?, ?)")
          .run(id, String(body.label ?? "untitled"), new Date().toISOString());
        return send(res, 201, { id });
      }

      const exhibitMatch = path.match(/^\/cases\/([^/]+)\/exhibits$/);
      if (method === "POST" && exhibitMatch) {
        const caseId = exhibitMatch[1];
        const exists = db.prepare("select 1 from cases where id = ?").get(caseId);
        if (!exists) return send(res, 404, { error: "unknown case" });
        const body = await readJson(req);
        const sha = String(body.sha256 ?? "");
        if (!/^[0-9a-f]{64}$/.test(sha)) return send(res, 400, { error: "sha256 must be 64 hex characters" });
        const id = addExhibit(db, caseId, sha, String(body.note ?? "").slice(0, 500));
        return send(res, 201, { exhibit_id: id });
      }

      const chainMatch = path.match(/^\/cases\/([^/]+)\/chain$/);
      if (method === "GET" && chainMatch) {
        const caseId = chainMatch[1];
        const rows = db.prepare("select id, sha256, note, prev_hash, chain_hash, created_at from exhibits where case_id = ? order by id").all(caseId);
        return send(res, 200, { exhibit_count: rows.length, ...verifyChain(db, caseId), entries: rows });
      }

      const runMatch = path.match(/^\/exhibits\/(\d+)\/runs$/);
      if (method === "POST" && runMatch) {
        const exhibitId = Number(runMatch[1]);
        const exists = db.prepare("select 1 from exhibits where id = ?").get(exhibitId);
        if (!exists) return send(res, 404, { error: "unknown exhibit" });
        const body = await readJson(req);
        const signals = body.signals;
        if (typeof signals !== "object" || signals === null) return send(res, 400, { error: "signals object required" });
        db.prepare("insert into runs (exhibit_id, level, signals, created_at) values (?, ?, ?, ?)")
          .run(exhibitId, String(body.level ?? "unknown").slice(0, 40), JSON.stringify(signals), new Date().toISOString());
        return send(res, 201, { ok: true });
      }

      if (method === "GET" && path === "/runs") {
        const exhibit = url.searchParams.get("exhibit");
        const rows = exhibit
          ? db.prepare("select id, exhibit_id, level, signals, created_at from runs where exhibit_id = ? order by id").all(Number(exhibit))
          : db.prepare("select id, exhibit_id, level, signals, created_at from runs order by id").all();
        return send(res, 200, { runs: rows });
      }

      return send(res, 404, { error: "no such route" });
    } catch (err) {
      const message = err instanceof Error ? err.message : "bad request";
      const code = message === "body too large" ? 413 : 400;
      return send(res, code, { error: message });
    }
  });
}

const isMain = process.argv[1] && import.meta.filename === process.argv[1];
if (isMain) {
  const dbPath = process.env.SEAM_DB ?? ":memory:";
  const db = openDb(dbPath);
  const server = makeServer(db);
  const port = Number(process.env.PORT ?? 8787);
  server.listen(port, "127.0.0.1", () => {
    console.log(`seam api on http://127.0.0.1:${port} (db ${dbPath})`);
  });
}
