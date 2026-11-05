/**
 * The chain is the only reason to store anything, so the tests are about it and not the routes.
 */
import { strict as assert } from "node:assert";
import { test } from "node:test";

import { addExhibit, linkHash, openDb, sha256, verifyChain } from "../src/server.ts";

test("an untouched chain verifies", () => {
  const db = openDb();
  db.prepare("insert into cases (id, label, created_at) values ('c1','demo',?)").run(new Date().toISOString());
  addExhibit(db, "c1", sha256("a"), "first");
  addExhibit(db, "c1", sha256("b"), "second");
  const result = verifyChain(db, "c1");
  assert.equal(result.ok, true);
  assert.equal(result.length, 2);
});

test("editing an exhibit breaks the chain at that link", () => {
  const db = openDb();
  db.prepare("insert into cases (id, label, created_at) values ('c1','demo',?)").run(new Date().toISOString());
  addExhibit(db, "c1", sha256("a"));
  const id = addExhibit(db, "c1", sha256("b"));
  db.prepare("update exhibits set note = ? where id = ?").run("rewritten", id);
  const result = verifyChain(db, "c1");
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, id);
});

test("removing an exhibit is visible even though every remaining row matches its own hash", () => {
  const db = openDb();
  db.prepare("insert into cases (id, label, created_at) values ('c1','demo',?)").run(new Date().toISOString());
  addExhibit(db, "c1", sha256("a"));
  const middle = addExhibit(db, "c1", sha256("b"));
  addExhibit(db, "c1", sha256("c"));
  db.prepare("delete from exhibits where id = ?").run(middle);
  const result = verifyChain(db, "c1");
  assert.equal(result.ok, false, "a deletion must not look like a clean shorter chain");
});

test("the link hash covers its predecessor, so reordering fails", () => {
  const prev = "0".repeat(64);
  assert.notEqual(linkHash(prev, sha256("a"), ""), linkHash(prev, sha256("b"), ""));
  assert.equal(linkHash(prev, sha256("a"), ""), linkHash(prev, sha256("a"), ""));
});
