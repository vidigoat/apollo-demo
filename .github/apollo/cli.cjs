#!/usr/bin/env node
/* Apollo CLI, bundled from github.com/vidigoat/apollo (b0c4e38) so this demo runs while that repository is private. MIT. */
var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};

// env.js
var require_env = __commonJS({
  "env.js"(exports2, module2) {
    var fs2 = require("node:fs");
    var path2 = require("node:path");
    var LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/;
    function parse(text) {
      const out = {};
      for (const raw of String(text).split(/\r?\n/)) {
        if (!raw.trim() || raw.trim().startsWith("#")) continue;
        const m = LINE.exec(raw);
        if (!m) continue;
        let value = m[2];
        if (value.startsWith('"') && value.endsWith('"') && value.length > 1 || value.startsWith("'") && value.endsWith("'") && value.length > 1) {
          value = value.slice(1, -1);
        }
        out[m[1]] = value;
      }
      return out;
    }
    var loaded = false;
    function loadEnv(file = path2.join(__dirname, ".env")) {
      if (loaded) return [];
      loaded = true;
      let text;
      try {
        text = fs2.readFileSync(file, "utf8");
      } catch {
        return [];
      }
      const set = [];
      for (const [key, value] of Object.entries(parse(text))) {
        if (process.env[key] !== void 0) continue;
        process.env[key] = value;
        set.push(key);
      }
      return set;
    }
    module2.exports = { loadEnv, parse };
  }
});

// transcript/schema.js
var require_schema = __commonJS({
  "transcript/schema.js"(exports2, module2) {
    var STRATEGIES = ["fsdiff", "proxy", "nodert", "ebpf"];
    var CAN_SEE = {
      fsdiff: { fs: true, net: false, dns: false, env: false, proc: false, exec: false },
      proxy: { fs: true, net: true, dns: true, env: false, proc: false, exec: false },
      /*
       * Node runtime instrumentation reaches every channel, but only through Node's own API surface —
       * a native addon or a captured reference goes underneath it. It is the only strategy that runs
       * without special infrastructure, and the only one that has actually run. See observe/probe.js.
       *
       * `exec` is the one thing it sees that eBPF cannot. Code built at runtime and handed to Function
       * or vm never becomes a syscall — it is a string turning into behaviour inside one process, and a
       * kernel tracer watches the process, not the thought. Being weaker almost everywhere and stronger
       * in exactly one place is why the strategy is worth keeping rather than replacing.
       *
       * ── `fs: 'writes'`, and why this entry used to say `true` ─────────────────
       *
       * The probe hooks writes and deletes only, deliberately: reads inside node_modules are what
       * `require` does all day and mean nothing. That is a good decision about what to RECORD and it
       * was being reported as though it were a decision about what could be SEEN.
       *
       * With `fs: true` here, every nodert transcript claimed the filesystem was watched — so a package
       * that read `~/.aws/credentials` at import time came back `quiet: true, blindTo: [],
       * trustworthy: true`. Reading a credential is the first step of the exact attack this project
       * exists to catch, and the index says 2,129 observations, 1,368 of them quiet, with not one
       * filesystem event among them. Some of that is packages genuinely writing nothing. None of it is
       * evidence that they read nothing, and the transcript was letting it read that way.
       *
       * So the value is what it is: writes, not reads. Anything other than `true` is a blind spot that
       * travels with the claim, which is what the rest of this file is for.
       */
      nodert: { fs: "writes", net: true, dns: true, env: true, proc: true, exec: true },
      ebpf: { fs: true, net: true, dns: true, env: true, proc: true, exec: false }
    };
    var STRENGTH = ["ebpf", "proxy", "nodert", "fsdiff"];
    var empty = () => ({ net: [], dns: [], fs: [], env: [], proc: [], exec: [] });
    var TEMP_DIR = /^\/(?:private\/)?(?:tmp|var\/folders)\/.*\/(?=[^/]+$)/;
    var NODE_CACHE = /\/(\.npm|\.cache|node_modules\/\.cache)\/.*/;
    var PID_LIKE = /\b\d{3,7}\b/g;
    var HASHY = /\b[0-9a-f]{8,64}\b/gi;
    function normalisePath(p) {
      return String(p).replace(TEMP_DIR, "/tmp/\xB7/").replace(NODE_CACHE, "/\xB7cache/\xB7").replace(HASHY, "\xB7").replace(PID_LIKE, "\xB7");
    }
    function normaliseNet(entry) {
      return { host: String(entry.host).toLowerCase(), port: Number(entry.port) || null, proto: entry.proto || "tcp" };
    }
    function normaliseProc(entry) {
      const argv = (entry.argv || []).map((a) => normalisePath(a));
      return { argv, cmd: argv[0] || "" };
    }
    var uniqueSorted = (items, key) => {
      const seen = /* @__PURE__ */ new Map();
      items.forEach((i) => seen.set(key(i), i));
      return [...seen.values()].sort((a, b) => key(a).localeCompare(key(b)));
    };
    function transcript({ pkg, version, strategy, raw = {}, timing = {}, result = {} }) {
      if (!STRATEGIES.includes(strategy)) {
        throw new Error(`Unknown observation strategy "${strategy}". A transcript must say how it was made.`);
      }
      const r = { ...empty(), ...raw };
      Object.keys(r).forEach((field) => {
        if (CAN_SEE[strategy][field] === false) r[field] = [];
      });
      const t = {
        pkg,
        version,
        strategy,
        canSee: CAN_SEE[strategy],
        ...channels(r),
        timing: { installMs: timing.installMs ?? null, importMs: timing.importMs ?? null },
        result: { installExit: result.installExit ?? null, importExit: result.importExit ?? null, threw: result.threw ?? null, reported: result.reported ?? null, installError: result.installError ?? null }
      };
      if (strategy === "nodert" && raw.install && typeof raw.install === "object") {
        t.install = channels({ ...empty(), ...raw.install });
      }
      return t;
    }
    function channels(r) {
      return {
        net: uniqueSorted(r.net.map(normaliseNet), (n) => `${n.host}:${n.port}/${n.proto}`),
        dns: [...new Set(r.dns.map((d) => String(d).toLowerCase()))].sort(),
        fs: uniqueSorted(
          r.fs.map((f) => ({ path: normalisePath(f.path), op: f.op })),
          (f) => `${f.op} ${f.path}`
        ),
        env: [...new Set(r.env.map(String))].sort(),
        proc: uniqueSorted(r.proc.map(normaliseProc), (p) => p.argv.join(" ")),
        // Code that did not exist until the program was running. `how` is the mechanism (Function, vm,
        // require of something undeclared); `sample` is a short, normalised excerpt — never the whole
        // payload, which can be megabytes and is not evidence, only volume.
        exec: uniqueSorted(
          r.exec.map((e) => ({ how: String(e.how || "unknown"), sample: normalisePath(String(e.sample || "").slice(0, 160)) })),
          (e) => `${e.how} ${e.sample}`
        )
      };
    }
    function unobserved(t) {
      const r = t?.result || {};
      if (r.installExit !== null && r.installExit !== void 0 && r.installExit !== 0) {
        return `${t.pkg}@${t.version} did not install (npm exited ${r.installExit}${r.installError ? `, ${r.installError}` : ""}), so nothing about it was seen`;
      }
      if (r.reported === false) return `the probe never reported for ${t.pkg}@${t.version}, so nothing about it was seen`;
      return null;
    }
    function observedNothing(t) {
      return t.net.length === 0 && t.dns.length === 0 && t.env.length === 0 && t.proc.length === 0 && t.fs.length === 0 && t.exec.length === 0;
    }
    function quietness(t) {
      const table = Object.entries(CAN_SEE[t.strategy] || {});
      const blindTo = table.filter(([, v]) => v !== true).map(([k]) => k);
      const partial = table.filter(([, v]) => v !== true && v !== false).map(([k, v]) => `${k} (${v} only)`);
      const quiet = observedNothing(t);
      return { quiet, blindTo, partial, trustworthy: quiet && blindTo.length === 0 };
    }
    module2.exports = { transcript, unobserved, observedNothing, quietness, normalisePath, STRATEGIES, STRENGTH, CAN_SEE, empty };
  }
});

// index/schema.js
var require_schema2 = __commonJS({
  "index/schema.js"(exports2, module2) {
    var fs2 = require("node:fs");
    var path2 = require("node:path");
    var crypto = require("node:crypto");
    var { CAN_SEE, unobserved } = require_schema();
    var SCHEMA = 1;
    var CHANNELS2 = ["net", "dns", "fs", "env", "proc", "exec"];
    var DEFAULT_DIR = process.env.APOLLO_INDEX || path2.join(__dirname, "data");
    function shardFor(name) {
      return crypto.createHash("sha256").update(String(name)).digest("hex").slice(0, 2);
    }
    function fileFor(dir, name) {
      return path2.join(dir, "entries", shardFor(name), `${encodeURIComponent(name)}.json`);
    }
    function entryFor(transcript) {
      const out = {
        version: transcript.version,
        strategy: transcript.strategy,
        canSee: transcript.canSee,
        observedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
      if (transcript.simulated) out.simulated = true;
      if (transcript.observedOn) out.observedOn = String(transcript.observedOn).slice(0, 60);
      for (const c of CHANNELS2) {
        if (Array.isArray(transcript[c])) out[c] = transcript[c];
      }
      if (transcript.install && typeof transcript.install === "object") {
        out.install = Object.fromEntries(CHANNELS2.filter((c) => Array.isArray(transcript.install[c])).map((c) => [c, transcript.install[c]]));
      }
      return out;
    }
    function restate(entry) {
      const table = CAN_SEE[entry?.strategy];
      if (table) entry.canSee = { ...table };
      return entry;
    }
    var Index2 = class {
      constructor({ dir = DEFAULT_DIR } = {}) {
        this.dir = dir;
        this.hits = 0;
        this.misses = 0;
        this._cache = /* @__PURE__ */ new Map();
      }
      /** @returns {object|null} the whole package record, or null. Never throws. */
      package(name) {
        if (this._cache.has(name)) return this._cache.get(name);
        let record = null;
        try {
          record = JSON.parse(fs2.readFileSync(fileFor(this.dir, name), "utf8"));
          if (record.schema !== SCHEMA) record = null;
          if (record) for (const entry of Object.values(record.versions || {})) restate(entry);
        } catch {
          record = null;
        }
        this._cache.set(name, record);
        return record;
      }
      /**
       * What did `name@version` do?
       *
       * @returns {object|null} an entry, or null when the index has never seen this version. Null is a
       *   real answer and callers must not treat it as "nothing happened" — see `apollo check`,
       *   which reports `unknown` as its own outcome rather than passing.
       */
      lookup(name, version) {
        const record = this.package(name);
        const entry = record?.versions?.[version] ?? null;
        if (entry) this.hits++;
        else this.misses++;
        return entry;
      }
      /** Every version of a package the index holds, newest-observed first. */
      versions(name) {
        const record = this.package(name);
        if (!record) return [];
        return Object.entries(record.versions || {}).map(([version, e]) => ({ version, ...e })).sort((a, b) => String(b.observedAt).localeCompare(String(a.observedAt)));
      }
      /** Write or replace one version's entry. Atomic, so a reader never sees half a file. */
      put(name, transcript) {
        const why = unobserved(transcript);
        if (why) throw new Error(`Refusing to index ${why}.`);
        const file = fileFor(this.dir, name);
        const existing = this.package(name) || { schema: SCHEMA, name, versions: {} };
        const entry = entryFor(transcript);
        const priorSimulated = Object.values(existing.versions).some((v) => v.simulated);
        const priorReal = Object.values(existing.versions).some((v) => !v.simulated);
        if (entry.simulated && priorReal) {
          throw new Error(
            `Refusing to write a simulated entry for ${name} into an index holding real observations. Build simulated runs into their own directory with --out.`
          );
        }
        if (!entry.simulated && priorSimulated) {
          throw new Error(
            `Refusing to write a real observation for ${name} into an index holding simulated entries. Delete the simulated index first.`
          );
        }
        existing.versions[transcript.version] = entry;
        existing.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
        fs2.mkdirSync(path2.dirname(file), { recursive: true });
        const tmp = `${file}.${process.pid}.tmp`;
        fs2.writeFileSync(tmp, JSON.stringify(existing, null, 2));
        fs2.renameSync(tmp, file);
        this._cache.set(name, existing);
        return existing;
      }
      has(name, version) {
        return this.lookup(name, version) !== null;
      }
      /** @returns {{revision, strategy, packages, versions, generatedAt}|null} */
      manifest() {
        try {
          return JSON.parse(fs2.readFileSync(path2.join(this.dir, "manifest.json"), "utf8"));
        } catch {
          return null;
        }
      }
      /**
       * Recount from the files themselves and rewrite the manifest.
       *
       * Counted rather than tracked, because a counter that drifts from the files is worse than no
       * counter: it is the number a README would quote.
       */
      writeManifest({ revision = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10), note = "" } = {}) {
        let packages = 0;
        let versions = 0;
        const strategies = /* @__PURE__ */ new Set();
        const entries = path2.join(this.dir, "entries");
        for (const shard of safeReaddir(entries)) {
          for (const f of safeReaddir(path2.join(entries, shard))) {
            try {
              const r = JSON.parse(fs2.readFileSync(path2.join(entries, shard, f), "utf8"));
              packages++;
              for (const v of Object.values(r.versions || {})) {
                versions++;
                if (v.strategy) strategies.add(v.strategy);
              }
            } catch {
            }
          }
        }
        const manifest = {
          schema: SCHEMA,
          revision,
          packages,
          versions,
          strategies: [...strategies].sort(),
          generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
          note
        };
        fs2.mkdirSync(this.dir, { recursive: true });
        fs2.writeFileSync(path2.join(this.dir, "manifest.json"), JSON.stringify(manifest, null, 2));
        return manifest;
      }
      summary() {
        const m = this.manifest();
        if (!m) return "no index built yet";
        return `${m.packages.toLocaleString()} packages \xB7 ${m.versions.toLocaleString()} versions \xB7 watched with ${m.strategies.join(", ") || "nothing"} \xB7 rev ${m.revision}`;
      }
    };
    var safeReaddir = (dir) => {
      try {
        return fs2.readdirSync(dir);
      } catch {
        return [];
      }
    };
    module2.exports = { Index: Index2, entryFor, fileFor, shardFor, SCHEMA, CHANNELS: CHANNELS2, DEFAULT_DIR };
  }
});

// index/published.js
var require_published = __commonJS({
  "index/published.js"(exports2, module2) {
    var fs2 = require("node:fs");
    var zlib = require("node:zlib");
    var { CAN_SEE } = require_schema();
    var { SCHEMA } = require_schema2();
    var PublishedIndex = class {
      constructor(doc, { from = "a published index" } = {}) {
        if (!doc || typeof doc !== "object") throw new Error(`${from} is not an index`);
        if (doc.schema !== SCHEMA) {
          throw new Error(
            `${from} is schema ${doc.schema ?? "unstated"} and this build reads schema ${SCHEMA}. Refusing to read it rather than guessing at the difference.`
          );
        }
        if (!doc.packages || typeof doc.packages !== "object") throw new Error(`${from} holds no packages`);
        this.doc = { ...doc, packages: Object.assign(/* @__PURE__ */ Object.create(null), doc.packages) };
        this.from = from;
        this.hits = 0;
        this.misses = 0;
      }
      package(name) {
        const versions = this.doc.packages[name];
        return versions ? { schema: SCHEMA, name, versions } : null;
      }
      /**
       * What did `name@version` do?
       *
       * Null means never observed. It does not mean "observed and quiet", and `checkLock` reports the
       * two as different outcomes — which is the only reason a published index is safe to hand to
       * somebody else's repository, where most of the tree will be unknown.
       */
      lookup(name, version) {
        const entry = this.doc.packages[name]?.[version] ?? null;
        if (entry) this.hits++;
        else this.misses++;
        if (entry && CAN_SEE[entry.strategy]) return { ...entry, canSee: { ...CAN_SEE[entry.strategy] } };
        return entry;
      }
      versions(name) {
        const all = this.doc.packages[name] || {};
        return Object.entries(all).map(([version, e]) => ({ version, ...this.lookup(name, version), version })).sort((a, b) => String(b.observedAt).localeCompare(String(a.observedAt)));
      }
      manifest() {
        return {
          schema: this.doc.schema,
          revision: this.doc.revision,
          packages: this.doc.counts?.packages ?? Object.keys(this.doc.packages).length,
          versions: this.doc.counts?.versions ?? 0,
          strategies: this.doc.strategies || [],
          generatedAt: this.doc.generatedAt,
          published: this.from
        };
      }
      summary() {
        const m = this.manifest();
        return `${m.versions.toLocaleString()} observations of ${m.packages.toLocaleString()} packages (${m.revision})`;
      }
      /**
       * Where the published table and this build's table disagree about what a strategy can see.
       *
       * Empty is the normal answer. When it is not, the index was published by a build with a different
       * idea of what was being watched, and a reader should be told rather than quietly given the local
       * interpretation of somebody else's recording.
       */
      mismatch() {
        const out = [];
        for (const [strategy, theirs] of Object.entries(this.doc.canSee || {})) {
          const ours = CAN_SEE[strategy];
          if (!ours) {
            out.push(`${strategy}: this build does not define it`);
            continue;
          }
          for (const channel of Object.keys(ours)) {
            if (String(ours[channel]) !== String(theirs[channel])) {
              out.push(`${strategy}.${channel}: published as ${JSON.stringify(theirs[channel])}, here it is ${JSON.stringify(ours[channel])}`);
            }
          }
        }
        return out;
      }
    };
    var MAX_INDEX = 128 * 1024 * 1024;
    async function open2(where, { fetchImpl = globalThis.fetch, timeoutMs = 2e4, maxBytes = MAX_INDEX } = {}) {
      if (/^https?:\/\//.test(where)) {
        const stop = AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : void 0;
        const res = await fetchImpl(where, { signal: stop, headers: { accept: "application/json" } });
        if (!res.ok) throw new Error(`${where} answered ${res.status}`);
        const declared = Number(res.headers?.get?.("content-length"));
        if (Number.isFinite(declared) && declared > maxBytes) {
          throw new Error(
            `${where} is ${(declared / 1048576).toFixed(0)} MB and this reads at most ${(maxBytes / 1048576).toFixed(0)} MB. Download it and pass the path instead.`
          );
        }
        const text2 = await res.text();
        if (text2.length > maxBytes) {
          throw new Error(
            `${where} sent ${(text2.length / 1048576).toFixed(0)} MB and this reads at most ${(maxBytes / 1048576).toFixed(0)} MB.`
          );
        }
        return new PublishedIndex(parse(text2, where), { from: where });
      }
      const raw = fs2.readFileSync(where);
      const text = raw[0] === 31 && raw[1] === 139 ? zlib.gunzipSync(raw).toString("utf8") : raw.toString("utf8");
      return new PublishedIndex(parse(text, where), { from: where });
    }
    function parse(text, where) {
      try {
        return JSON.parse(text);
      } catch {
        const head = text.slice(0, 60).replace(/\s+/g, " ");
        throw new Error(`${where} did not return an index \u2014 it returned: ${head}\u2026`);
      }
    }
    module2.exports = { PublishedIndex, open: open2, MAX_INDEX };
  }
});

// lockfile.js
var require_lockfile = __commonJS({
  "lockfile.js"(exports2, module2) {
    var { execFile } = require("node:child_process");
    var { promisify } = require("node:util");
    var fs2 = require("node:fs");
    var path2 = require("node:path");
    var run = promisify(execFile);
    var isRoot = (key) => key === "" || key === ".";
    function nameFromPath(key) {
      const parts = key.split("node_modules/");
      return parts[parts.length - 1] || null;
    }
    function parseLockfile(text) {
      let json;
      try {
        json = JSON.parse(text);
      } catch (e) {
        throw new Error(`That is not a lockfile: ${e.message}`);
      }
      const versions = /* @__PURE__ */ new Map();
      const conflicts = /* @__PURE__ */ new Map();
      const platforms = /* @__PURE__ */ new Map();
      const installScripts = /* @__PURE__ */ new Set();
      let format;
      const record = (name, version) => {
        if (!name || !version || typeof version !== "string") return;
        if (!/^\d+\.\d+\.\d+/.test(version)) return;
        const existing = versions.get(name);
        if (existing && existing !== version) {
          const seen = conflicts.get(name) || /* @__PURE__ */ new Set([existing]);
          seen.add(version);
          conflicts.set(name, seen);
        }
        versions.set(name, version);
      };
      if (json.packages && typeof json.packages === "object") {
        format = json.lockfileVersion === 2 ? "v2" : "v3";
        for (const [key, node] of Object.entries(json.packages)) {
          if (isRoot(key) || !node) continue;
          if (!key.includes("node_modules/") || node.link) continue;
          const name = typeof node.name === "string" && node.name ? node.name : nameFromPath(key);
          record(name, node.version);
          if (node.os || node.cpu || node.libc) platforms.set(`${name}@${node.version}`, { os: node.os, cpu: node.cpu, libc: node.libc });
          if (node.hasInstallScript && /^\d+\.\d+\.\d+/.test(String(node.version))) installScripts.add(`${name}@${node.version}`);
        }
      } else if (json.dependencies && typeof json.dependencies === "object") {
        format = "v1";
        const stack = [json.dependencies];
        while (stack.length) {
          const deps = stack.pop();
          if (!deps || typeof deps !== "object") continue;
          for (const [name, node] of Object.entries(deps)) {
            if (!node) continue;
            record(name, node.version);
            if (node.dependencies) stack.push(node.dependencies);
          }
        }
      } else {
        throw new Error(
          `Unrecognised lockfile: no "packages" or "dependencies" (lockfileVersion ${json.lockfileVersion ?? "absent"}). Refusing to report an empty tree, which would read as "nothing to check".`
        );
      }
      return {
        format,
        lockfileVersion: json.lockfileVersion ?? null,
        name: json.name ?? null,
        total: versions.size,
        versions,
        platforms,
        installScripts,
        conflicts: [...conflicts.entries()].map(([name, set]) => ({ name, versions: [...set] }))
      };
    }
    function installsOnLinux2({ os, cpu, libc } = {}) {
      const fits = (list, value) => {
        if (!Array.isArray(list) || !list.length) return true;
        if (list.includes(`!${value}`)) return false;
        const positive = list.filter((x) => !String(x).startsWith("!"));
        return positive.length ? positive.includes(value) : true;
      };
      return fits(os, "linux") && fits(cpu, "x64") && fits(libc, "glibc");
    }
    function whatMoved2(before, after) {
      const moved = [];
      const added = [];
      const removed = [];
      for (const [name, to] of after.versions) {
        const from = before.versions.get(name);
        if (from === void 0) added.push({ pkg: name, version: to });
        else if (from !== to) moved.push({ pkg: name, from, to });
      }
      for (const [name, from] of before.versions) {
        if (!after.versions.has(name)) removed.push({ pkg: name, version: from });
      }
      moved.sort((a, b) => a.pkg.localeCompare(b.pkg));
      return {
        moved,
        added,
        removed,
        unchanged: after.versions.size - moved.length - added.length,
        total: after.versions.size
      };
    }
    async function lockfileAtRevision2(revision, file = "package-lock.json", cwd = process.cwd()) {
      try {
        const { stdout } = await run("git", ["show", `${revision}:${file}`], {
          cwd,
          maxBuffer: 64 * 1024 * 1024
        });
        return parseLockfile(stdout);
      } catch (e) {
        const why = String(e.stderr || e.message).split("\n")[0];
        if (/does not exist|exists on disk, but not in/.test(why)) {
          throw new Error(`No ${file} at ${revision}. Nothing to compare against.`);
        }
        throw new Error(`Could not read ${file} at ${revision}: ${why}`);
      }
    }
    function lockfileOnDisk2(file = "package-lock.json", cwd = process.cwd()) {
      const full = path2.isAbsolute(file) ? file : path2.join(cwd, file);
      if (!fs2.existsSync(full)) throw new Error(`No lockfile at ${full}.`);
      return parseLockfile(fs2.readFileSync(full, "utf8"));
    }
    module2.exports = { parseLockfile, installsOnLinux: installsOnLinux2, whatMoved: whatMoved2, lockfileAtRevision: lockfileAtRevision2, lockfileOnDisk: lockfileOnDisk2, nameFromPath };
  }
});

// differ/diff.js
var require_diff = __commonJS({
  "differ/diff.js"(exports2, module2) {
    var { quietness, unobserved } = require_schema();
    var procText = (p) => p && typeof p === "object" && Array.isArray(p.argv) ? p.argv.join(" ") : String(p);
    var keyFor = {
      net: (n) => `${n.host}:${n.port ?? ""}/${n.proto}`,
      dns: (d) => d,
      fs: (f) => `${f.op} ${f.path}`,
      env: (e) => e,
      proc: (p) => procText(p),
      exec: (e) => `${e.how} ${e.sample}`
    };
    function setDiff(before, after, key) {
      const b = new Map(before.map((x) => [key(x), x]));
      const a = new Map(after.map((x) => [key(x), x]));
      return {
        added: [...a.keys()].filter((k) => !b.has(k)).map((k) => a.get(k)),
        removed: [...b.keys()].filter((k) => !a.has(k)).map((k) => b.get(k))
      };
    }
    var SENSITIVE_ENV = /(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AWS_|GITHUB_|NPM_|SSH|PRIVATE)/i;
    var readsCredential = (name) => {
      const n = String(name);
      if (/^npm_(config|package|lifecycle)_|^npm_(command|execpath|node_execpath|user_agent)$/i.test(n)) {
        return /(auth|token|password|passwd|secret|_key|keyfile|cert)/i.test(n);
      }
      return /(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|(^|_)KEY(_|$)|API_?KEY|ACCESS_?KEY|KEYFILE|(^|_)AUTH(_|$)|SSH_AUTH_SOCK|_PAT$)/i.test(n);
    };
    var NOTABLE_PROC = /\b(curl|wget|sh|bash|zsh|powershell|nc|python|node\s+-e|eval)\b/i;
    var BUILDS_CODE = /^(Function|vm\.)/;
    function severityOf(input) {
      const none = { added: [], removed: [] };
      const d = { net: none, dns: none, fs: none, env: none, proc: none, exec: none, ...input };
      const reasons = [];
      if (d.env.added.some(readsCredential)) reasons.push("reads a credential it did not read before");
      if (d.proc.added.some((p) => NOTABLE_PROC.test(procText(p)))) reasons.push("spawns a shell or a downloader it did not spawn before");
      const built = d.exec.added.filter((e) => BUILDS_CODE.test(e.how));
      if (built.length) {
        reasons.push(`builds and runs code that did not exist in the source (${built.map((e) => e.how).join(", ")})`);
      }
      if (reasons.length) return { level: "alarming", reasons };
      if (d.net.added.length) reasons.push(`talks to ${d.net.added.length} destination${d.net.added.length === 1 ? "" : "s"} it did not talk to before`);
      if (d.dns.added.length && !d.net.added.length) reasons.push("resolves a name it did not resolve before");
      if (reasons.length) return { level: "notable", reasons };
      if (d.fs.added.length) reasons.push("writes somewhere it did not write before");
      else if (d.fs.removed.length) reasons.push("stopped writing or deleting somewhere it did before");
      if (d.proc.added.length) reasons.push("spawns a process it did not spawn before");
      const envCount = d.env.added.length;
      if (envCount) reasons.push(`reads ${envCount} environment variable${envCount === 1 ? "" : "s"} it did not read before`);
      if (d.exec.added.length) reasons.push("decodes something it did not decode before");
      if (reasons.length) return { level: "minor", reasons };
      return { level: "none", reasons: [] };
    }
    function diff(before, after) {
      if (before.pkg !== after.pkg) {
        throw new Error(`Cannot compare different packages: ${before.pkg} and ${after.pkg}`);
      }
      if (before.strategy !== after.strategy) {
        throw new Error(
          `Cannot compare a "${before.strategy}" transcript with a "${after.strategy}" one \u2014 the difference would be in how we watched, not in what the package did.`
        );
      }
      const unseen = [before, after].map(unobserved).filter(Boolean);
      if (unseen.length) {
        const e = new Error(`Not watched: ${unseen.join("; ")}. That is not the same as clean.`);
        e.code = "UNOBSERVED";
        throw e;
      }
      const parts = {};
      ["net", "dns", "fs", "env", "proc", "exec"].forEach((field) => {
        parts[field] = setDiff(before[field], after[field], keyFor[field]);
      });
      const qb = quietness(before);
      const qa = quietness(after);
      const importSeverity = severityOf(parts);
      let install = null;
      let severity = importSeverity;
      if (before.install && after.install) {
        install = {};
        ["net", "dns", "fs", "env", "proc", "exec"].forEach((field) => {
          install[field] = setDiff(before.install[field] || [], after.install[field] || [], keyFor[field]);
        });
        const s = severityOf(install);
        const ORDER = ["none", "minor", "notable", "alarming"];
        severity = {
          level: ORDER[Math.max(ORDER.indexOf(importSeverity.level), ORDER.indexOf(s.level))],
          reasons: [...importSeverity.reasons, ...s.reasons.map((r) => `at install: ${r}`)]
        };
      }
      const changed = [...Object.values(parts), ...Object.values(install || {})].some((p) => p.added.length || p.removed.length);
      const importDelta = before.timing.importMs != null && after.timing.importMs != null ? after.timing.importMs - before.timing.importMs : null;
      return {
        pkg: before.pkg,
        from: before.version,
        to: after.version,
        strategy: before.strategy,
        // Said on every diff. A quiet result from a run that could not see the network is not evidence
        // of quiet behaviour, and the report has to carry that caveat with it.
        canSee: before.canSee,
        changed,
        ...parts,
        // Present only when both sides watched the install phase.
        ...install ? { install } : {},
        timing: { importDeltaMs: importDelta },
        severity: severity.level,
        reasons: severity.reasons,
        /*
         * "Both versions did nothing" — and how much that is worth.
         *
         * `bothQuiet` alone is a trap: `transcript()` deletes the channels a strategy cannot see, so a
         * package exfiltrating a credential under `fsdiff` produces six empty arrays and reads as quiet.
         * `quietTrustworthy` is the only one of these that supports the sentence "it did nothing", and
         * `blindTo` names what silence cannot speak for. They travel together so that no consumer can
         * pick up the claim without the caveat attached to the same object.
         */
        bothQuiet: qb.quiet && qa.quiet,
        quietTrustworthy: qb.trustworthy && qa.trustworthy,
        blindTo: qb.blindTo
      };
    }
    function summarise(d) {
      if (d.changed) return `${d.pkg} ${d.from} \u2192 ${d.to}: ${d.reasons.join("; ")}`;
      const qualified = d.blindTo && d.blindTo.length ? `no change in what ${d.strategy} can see` : "no behavioural change";
      return `${d.pkg} ${d.from} \u2192 ${d.to}: ${qualified}`;
    }
    module2.exports = { diff, summarise, severityOf, SENSITIVE_ENV, readsCredential, NOTABLE_PROC, BUILDS_CODE };
  }
});

// github/bump.js
var require_bump = __commonJS({
  "github/bump.js"(exports2, module2) {
    var { diff } = require_diff();
    var { CHANNELS: CHANNELS2 } = require_schema2();
    var ORDER = ["none", "minor", "notable", "alarming"];
    var own = (o, k) => o && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : void 0;
    var short = (x) => (typeof x === "string" ? x : JSON.stringify(x)).slice(0, 120);
    function gainedOf(d) {
      const out = {};
      for (const c of CHANNELS2) {
        const a = (d[c]?.added || []).map(short);
        const r = (d[c]?.removed || []).map(short);
        if (a.length || r.length) out[c] = { added: a, removed: r };
        const ia = (d.install?.[c]?.added || []).map(short);
        const ir = (d.install?.[c]?.removed || []).map(short);
        if (ia.length || ir.length) out[`install.${c}`] = { added: ia, removed: ir };
      }
      return out;
    }
    var asTranscript = (e, pkg, version) => ({
      ...Object.fromEntries(CHANNELS2.map((c) => [c, Array.isArray(e[c]) ? e[c] : []])),
      ...e.install ? { install: Object.fromEntries(CHANNELS2.map((c) => [c, e.install[c] || []])) } : {},
      pkg,
      version,
      strategy: e.strategy,
      canSee: e.canSee,
      timing: {}
    });
    function bumpReport2(moved, { index = null, ledger = null } = {}) {
      const changed = [];
      const same = [];
      const unknown = [];
      const pairs = ledger && typeof ledger === "object" ? ledger.pairs : null;
      for (const m of Array.isArray(moved) ? moved : []) {
        if (!m || typeof m.pkg !== "string" || typeof m.from !== "string" || typeof m.to !== "string") continue;
        const base = { pkg: m.pkg, from: m.from, to: m.to };
        const seen = own(own(pairs, m.pkg), `${m.from}\u2192${m.to}`);
        if (seen && ORDER.includes(seen.severity)) {
          const row = { ...base, severity: seen.severity, reasons: seen.reasons || [], gained: seen.gained || {}, explained: seen.explained || null, source: "watched as a pair when it was published" };
          (seen.severity === "none" ? same : changed).push(row);
          continue;
        }
        let a = null;
        let b = null;
        try {
          a = index?.lookup(m.pkg, m.from);
          b = index?.lookup(m.pkg, m.to);
        } catch {
          a = b = null;
        }
        if (a && b) {
          try {
            const d = diff(asTranscript(a, m.pkg, m.from), asTranscript(b, m.pkg, m.to));
            const row = { ...base, severity: d.severity, reasons: d.reasons || [], gained: gainedOf(d), explained: null, source: "both versions in the index" };
            (d.severity === "none" ? same : changed).push(row);
            continue;
          } catch {
          }
        }
        const hops = Object.entries(own(pairs, m.pkg) || {}).filter(([k]) => k.endsWith(`\u2192${m.to}`)).map(([k, v]) => ({ against: k.split("\u2192")[0], severity: v.severity, reasons: v.reasons || [] }));
        unknown.push({ ...base, ...hops.length ? { nearest: hops[0] } : {} });
      }
      const rank = (r) => ORDER.indexOf(r.severity);
      changed.sort((x, y) => rank(y) - rank(x) || x.pkg.localeCompare(y.pkg));
      return { changed, same, unknown };
    }
    function readable2(item) {
      let x = item;
      if (typeof item === "string" && item.startsWith("{")) {
        try {
          x = JSON.parse(item);
        } catch {
          return item;
        }
      }
      if (!x || typeof x !== "object") return String(x);
      if (Array.isArray(x.argv)) return x.argv.filter(Boolean).join(" ");
      if (x.how) return x.sample ? `${x.how}(${JSON.stringify(String(x.sample).slice(0, 60))})` : x.how;
      if (x.host) return `${x.host}${x.port ? `:${x.port}` : ""}`;
      if (x.path) return `${x.op || ""} ${x.path}`.trim();
      return JSON.stringify(x);
    }
    function evidence(gained) {
      const lines = [];
      for (const [channel, g] of Object.entries(gained && typeof gained === "object" ? gained : {})) {
        if (!g || typeof g !== "object") continue;
        const where = channel.startsWith("install.") ? `at install, ${channel.slice(8)}` : channel;
        if (Array.isArray(g.added) && g.added.length) lines.push(`${where}: now \`${g.added.slice(0, 6).map(readable2).join("`, `")}\`${g.added.length > 6 ? ` and ${g.added.length - 6} more` : ""}`);
        if (Array.isArray(g.removed) && g.removed.length) lines.push(`${where}: no longer \`${g.removed.slice(0, 4).map(readable2).join("`, `")}\``);
      }
      return lines;
    }
    module2.exports = { bumpReport: bumpReport2, evidence, gainedOf, readable: readable2, ORDER };
  }
});

// lock.js
var require_lock = __commonJS({
  "lock.js"(exports2, module2) {
    var fs2 = require("node:fs");
    var path2 = require("node:path");
    var { CHANNELS: CHANNELS2 } = require_schema2();
    var LOCK_VERSION = 1;
    var DEFAULT_FILE2 = "apollo.lock";
    function stable(value) {
      if (Array.isArray(value)) {
        return value.map(stable).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
      }
      if (value && typeof value === "object") {
        const out = {};
        for (const k of Object.keys(value).sort()) out[k] = stable(value[k]);
        return out;
      }
      return value;
    }
    function buildLock2(tree, index) {
      const pairs = tree instanceof Map ? [...tree.entries()] : Object.entries(tree);
      const packages = {};
      const unknown = [];
      const strategies = /* @__PURE__ */ new Set();
      for (const [name, version] of pairs.sort(([a], [b]) => a.localeCompare(b))) {
        const entry = index.lookup(name, version);
        if (!entry) {
          unknown.push(`${name}@${version}`);
          continue;
        }
        const record = { strategy: entry.strategy };
        strategies.add(entry.strategy);
        for (const c of CHANNELS2) {
          if (Array.isArray(entry[c])) record[c] = entry[c];
        }
        if (entry.install) record.install = Object.fromEntries(CHANNELS2.filter((c) => Array.isArray(entry.install[c])).map((c) => [c, entry.install[c]]));
        packages[`${name}@${version}`] = stable(record);
      }
      const manifest = index.manifest();
      return {
        known: Object.keys(packages).length,
        unknown,
        lock: {
          lockfileVersion: LOCK_VERSION,
          // Which index produced this. Without it, a lock cannot be re-checked against the same facts
          // six months later, and "the answer changed" becomes indistinguishable from "the index did".
          index: {
            revision: manifest?.revision ?? "unknown",
            packages: manifest?.packages ?? null
          },
          strategies: [...strategies].sort(),
          generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
          packages: stable(packages),
          unknown: unknown.sort()
        }
      };
    }
    function checkLock2(lock, tree, index) {
      const pairs = tree instanceof Map ? [...tree.entries()] : Object.entries(tree);
      const drift = [];
      const unknown = [];
      const added = [];
      let checked = 0;
      for (const [name, version] of pairs.sort(([a], [b]) => a.localeCompare(b))) {
        const key = `${name}@${version}`;
        const was = lock.packages?.[key];
        const now = index.lookup(name, version);
        if (!now) {
          unknown.push(key);
          continue;
        }
        if (!was) {
          added.push(key);
          continue;
        }
        checked++;
        const changes = [];
        for (const c of CHANNELS2) {
          const before = Array.isArray(was[c]) ? stable(was[c]) : null;
          const after = Array.isArray(now[c]) ? stable(now[c]) : null;
          if (JSON.stringify(before) !== JSON.stringify(after)) {
            changes.push({ channel: c, before, after });
          }
        }
        if (was.install && now.install) {
          for (const c of CHANNELS2) {
            const before = Array.isArray(was.install[c]) ? stable(was.install[c]) : null;
            const after = Array.isArray(now.install[c]) ? stable(now.install[c]) : null;
            if (JSON.stringify(before) !== JSON.stringify(after)) changes.push({ channel: `install.${c}`, before, after });
          }
        }
        if (changes.length) drift.push({ package: key, changes });
      }
      return {
        clean: drift.length === 0,
        checked,
        drift,
        unknown: unknown.sort(),
        added: added.sort()
      };
    }
    function writeLock2(lock, file = DEFAULT_FILE2) {
      const abs = path2.resolve(file);
      fs2.writeFileSync(abs, `${JSON.stringify(lock, null, 2)}
`);
      return abs;
    }
    function readLock2(file = DEFAULT_FILE2) {
      const abs = path2.resolve(file);
      let text;
      try {
        text = fs2.readFileSync(abs, "utf8");
      } catch {
        return null;
      }
      const parsed = JSON.parse(text);
      if (parsed.lockfileVersion !== LOCK_VERSION) {
        throw new Error(
          `${file} was written by lockfile version ${parsed.lockfileVersion}; this is version ${LOCK_VERSION}. Re-run \`apollo lock\` rather than trusting a format this does not know.`
        );
      }
      return parsed;
    }
    module2.exports = { buildLock: buildLock2, checkLock: checkLock2, writeLock: writeLock2, readLock: readLock2, stable, LOCK_VERSION, DEFAULT_FILE: DEFAULT_FILE2 };
  }
});

// cli.js
require_env().loadEnv();
var fs = require("node:fs");
var path = require("node:path");
var { Index } = require_schema2();
var { open } = require_published();
var { lockfileOnDisk, lockfileAtRevision, whatMoved, installsOnLinux } = require_lockfile();
var { bumpReport, readable } = require_bump();
var { buildLock, checkLock, writeLock, readLock, DEFAULT_FILE } = require_lock();
var { CHANNELS } = require_schema2();
var C = process.stdout.isTTY ? { red: "\x1B[31m", green: "\x1B[32m", amber: "\x1B[33m", dim: "\x1B[2m", bold: "\x1B[1m", off: "\x1B[0m" } : { red: "", green: "", amber: "", dim: "", bold: "", off: "" };
var EXIT = { clean: 0, drift: 1, unknown: 2, usage: 3 };
var die = (msg, hint) => {
  console.error(`
  ${C.red}${msg}${C.off}`);
  if (hint) console.error(`  ${C.dim}${hint}${C.off}`);
  console.error("");
  process.exit(EXIT.usage);
};
function parseArgs(argv) {
  const flags = {};
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      rest.push(a);
      continue;
    }
    const [k, inline] = a.slice(2).split("=");
    flags[k] = inline ?? (argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true);
  }
  return { flags, rest };
}
var plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
function renderItem(channel, item) {
  if (typeof item === "string") return item;
  if (channel === "net") return `${item.host}:${item.port ?? ""}${item.proto ? "/" + item.proto : ""}`;
  if (channel === "fs") return `${item.op} ${item.path}`;
  if (channel === "proc") return (item.argv || []).join(" ");
  if (channel === "exec") return `${item.how} ${item.sample ?? ""}`.trim();
  return JSON.stringify(item);
}
async function cmdLock({ flags }) {
  const index = await openIndex(flags);
  let tree;
  try {
    tree = lockfileOnDisk(flags.lockfile || "package-lock.json");
  } catch (e) {
    die(e.message, "Run this from a directory with a package-lock.json, or pass --lockfile <path>.");
  }
  const { lock, known, unknown } = buildLock(tree.versions, index);
  const out = flags.out || DEFAULT_FILE;
  if (flags["dry-run"]) {
    console.log(`
  ${C.bold}${out}${C.off} ${C.dim}(dry run \u2014 nothing written)${C.off}`);
  } else {
    writeLock(lock, out);
    console.log(`
  ${C.green}wrote${C.off} ${C.bold}${out}${C.off}`);
  }
  console.log(`  ${C.dim}${plural(known, "package")} pinned from ${index.summary()}${C.off}`);
  if (unknown.length) {
    console.log(`  ${C.amber}${plural(unknown.length, "package")} the index has never seen${C.off}`);
    for (const u of unknown.slice(0, 8)) console.log(`      ${C.dim}${u}${C.off}`);
    if (unknown.length > 8) console.log(`      ${C.dim}\u2026 and ${unknown.length - 8} more, all listed in ${out}${C.off}`);
    const elsewhere = unknown.filter((id) => tree.platforms?.has(id) && !installsOnLinux(tree.platforms.get(id)));
    if (elsewhere.length) {
      console.log(`  ${C.dim}${elsewhere.length} of them ${elsewhere.length === 1 ? "is" : "are"} built only for another platform (macOS, Windows, musl), so not installable where the index is observed.${C.off}`);
    }
    console.log(`  ${C.dim}They are recorded under "unknown" \u2014 the lock does not pretend to cover them.${C.off}`);
  }
  console.log("");
  return EXIT.clean;
}
async function openIndex(flags) {
  const where = flags.index === true ? null : flags.index;
  if (!where) {
    const index = new Index();
    if (!index.manifest()) {
      die(
        "No index found.",
        "Build one with `npm run index:build`, point APOLLO_INDEX at one,\n  or use a published one:\n\n    apollo check --index https://apollo-watch.vercel.app/index.json"
      );
    }
    return index;
  }
  try {
    const index = await open(where);
    const differs = index.mismatch();
    if (differs.length) {
      console.error(`
  ${C.amber}That index was published by a build that describes its strategies differently:${C.off}`);
      for (const line of differs) console.error(`    ${C.dim}${line}${C.off}`);
      console.error(`  ${C.dim}Entries are read with THIS build's table, because that is what interprets them.${C.off}`);
    }
    return index;
  } catch (e) {
    die(`Could not read the index at ${where}.`, e.message);
  }
  return null;
}
async function cmdCheck({ flags }) {
  const index = await openIndex(flags);
  let lock;
  try {
    lock = readLock(flags.lock || DEFAULT_FILE);
  } catch (e) {
    die(e.message);
  }
  if (!lock) {
    die(`No ${flags.lock || DEFAULT_FILE} to check against.`, "Run `apollo lock` first and commit the result.");
  }
  let tree;
  try {
    tree = lockfileOnDisk(flags.lockfile || "package-lock.json");
  } catch (e) {
    die(e.message);
  }
  const result = checkLock(lock, tree.versions, index);
  console.log(`
  ${C.bold}apollo check${C.off} ${C.dim}\xB7 ${plural(result.checked, "package")} checked against ${lock.index?.revision ?? "an unknown index"}${C.off}`);
  if (result.drift.length) {
    console.log(`
  ${C.red}${plural(result.drift.length, "package")} behaves differently than the lock records${C.off}
`);
    for (const d of result.drift) {
      console.log(`  ${C.bold}${d.package}${C.off}`);
      for (const ch of d.changes) {
        const gone = (ch.before || []).filter((b) => !(ch.after || []).some((a) => JSON.stringify(a) === JSON.stringify(b)));
        const came = (ch.after || []).filter((a) => !(ch.before || []).some((b) => JSON.stringify(b) === JSON.stringify(a)));
        for (const item of came) console.log(`      ${C.red}+ ${ch.channel.padEnd(5)} ${renderItem(ch.channel, item)}${C.off}`);
        for (const item of gone) console.log(`      ${C.dim}- ${ch.channel.padEnd(5)} ${renderItem(ch.channel, item)}${C.off}`);
      }
      console.log("");
    }
  }
  if (result.added.length) {
    console.log(`  ${C.dim}${plural(result.added.length, "package")} added since the lock was written \u2014 not drift, there is nothing to have drifted from:${C.off}`);
    for (const a of result.added.slice(0, 5)) console.log(`      ${C.dim}${a}${C.off}`);
    if (result.added.length > 5) console.log(`      ${C.dim}\u2026 and ${result.added.length - 5} more${C.off}`);
    console.log(`  ${C.dim}Re-run \`apollo lock\` to pin them.${C.off}
`);
  }
  if (result.unknown.length) {
    console.log(`  ${C.amber}${plural(result.unknown.length, "package")} the index has never seen${C.off}`);
    console.log(`  ${C.dim}Not a pass and not a failure \u2014 an honest "I do not know".${C.off}
`);
  }
  if (result.clean && !result.unknown.length) {
    console.log(`  ${C.green}clean${C.off} ${C.dim}\u2014 every package does exactly what the lock says it does${C.off}
`);
    return EXIT.clean;
  }
  if (result.drift.length) return EXIT.drift;
  if (result.unknown.length && flags["fail-on-unknown"]) return EXIT.unknown;
  console.log(`  ${C.green}no drift${C.off}
`);
  return EXIT.clean;
}
async function openWatched(flags) {
  const where = typeof flags.watched === "string" ? flags.watched : typeof flags.index === "string" && /^https?:/.test(flags.index) ? new URL("watched-releases.json", flags.index).href : path.join(__dirname, "public", "watched-releases.json");
  try {
    if (/^https?:/.test(where)) {
      const res = await fetch(where, { signal: AbortSignal.timeout(2e4) });
      if (!res.ok) throw new Error(`${res.status}`);
      return { ledger: await res.json(), where };
    }
    return { ledger: JSON.parse(fs.readFileSync(where, "utf8")), where };
  } catch {
    return { ledger: null, where };
  }
}
async function cmdUpgrade({ flags }) {
  const index = await openIndex(flags);
  const against = typeof flags.against === "string" ? flags.against : "HEAD";
  const file = flags.lockfile || "package-lock.json";
  let before;
  let after;
  try {
    before = await lockfileAtRevision(against, file);
    after = lockfileOnDisk(file);
  } catch (e) {
    die(e.message);
  }
  const { moved } = whatMoved(before, after);
  const { ledger, where } = await openWatched(flags);
  console.log(`
  ${C.bold}apollo upgrade${C.off} ${C.dim}\xB7 ${plural(moved.length, "version")} moved since ${against}${ledger ? ` \xB7 ${ledger.count ?? "?"} watched release pairs` : ` \xB7 no watched releases at ${where}`}${C.off}`);
  if (!moved.length) {
    console.log(`
  ${C.dim}Nothing was upgraded, so there is nothing to compare.${C.off}
`);
    return EXIT.clean;
  }
  const r = bumpReport(moved, { index, ledger });
  const loud = r.changed.filter((c) => c.severity === "alarming" || c.severity === "notable");
  for (const c of r.changed) {
    const tone = c.severity === "minor" ? C.amber : C.red;
    console.log(`
  ${tone}${c.severity}${C.off}  ${C.bold}${c.pkg}${C.off} ${c.from} \u2192 ${c.to}  ${C.dim}${(c.reasons || []).join("; ")}${C.off}`);
    for (const [channel, g] of Object.entries(c.gained || {})) {
      const where2 = channel.startsWith("install.") ? `at install, ${channel.slice(8)}` : channel;
      for (const item of (g.added || []).slice(0, 8)) console.log(`      ${tone}+ ${where2.padEnd(5)} ${readable(item)}${C.off}`);
      for (const item of (g.removed || []).slice(0, 4)) console.log(`      ${C.dim}- ${where2.padEnd(5)} ${readable(item)}${C.off}`);
    }
    if (c.explained) console.log(`      ${C.dim}${c.explained}${C.off}`);
    console.log(`      ${C.dim}${c.source}${C.off}`);
  }
  if (r.same.length) {
    console.log(`
  ${C.green}${plural(r.same.length, "upgrade")} compared, behaving the same as before${C.off}`);
    console.log(`      ${C.dim}${r.same.slice(0, 8).map((x) => `${x.pkg} ${x.to}`).join(", ")}${r.same.length > 8 ? `, and ${r.same.length - 8} more` : ""}${C.off}`);
  }
  if (r.unknown.length) {
    console.log(`
  ${C.amber}${plural(r.unknown.length, "upgrade")} nobody has compared${C.off}`);
    console.log(`  ${C.dim}Not a pass and not a failure \u2014 an honest "I do not know".${C.off}`);
    for (const u of r.unknown.slice(0, 8)) {
      console.log(`      ${C.dim}${u.pkg} ${u.from} \u2192 ${u.to}${u.nearest ? ` \u2014 ${u.to} was watched against ${u.nearest.against}: ${u.nearest.severity}` : ""}${C.off}`);
    }
    if (r.unknown.length > 8) console.log(`      ${C.dim}\u2026 and ${r.unknown.length - 8} more${C.off}`);
  }
  if (loud.length) {
    console.log(`
  ${C.red}${plural(loud.length, "upgrade")} to read before merging.${C.off} ${C.dim}That is what "alarming" means here \u2014 never "malicious".${C.off}
`);
    return EXIT.drift;
  }
  if (r.unknown.length && flags["fail-on-unknown"]) {
    console.log("");
    return EXIT.unknown;
  }
  console.log(`
  ${C.green}nothing to stop for${C.off}
`);
  return EXIT.clean;
}
async function cmdExplain({ flags, rest }) {
  const spec = rest[0];
  if (!spec) die("Which package?", "apollo explain lodash            \u2014 every version the index holds\napollo explain lodash@4.17.21   \u2014 one version");
  const at = spec.lastIndexOf("@");
  const name = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : null;
  const index = await openIndex(flags);
  const entries = version ? [index.lookup(name, version)].filter(Boolean).map((e) => ({ version, ...e })) : index.versions(name);
  if (!entries.length) {
    console.log(`
  ${C.amber}The index has never seen ${spec}.${C.off}`);
    console.log(`  ${C.dim}That is an absence of evidence, not evidence of absence.${C.off}
`);
    return EXIT.clean;
  }
  console.log(`
  ${C.bold}${name}${C.off}
`);
  for (const e of entries) {
    const blind = Object.entries(e.canSee || {}).filter(([, v]) => !v).map(([k]) => k);
    console.log(`  ${C.bold}${e.version}${C.off} ${C.dim}\xB7 watched with ${e.strategy}${C.off}`);
    let said = false;
    for (const c of CHANNELS) {
      if (!Array.isArray(e[c]) || !e[c].length) continue;
      said = true;
      for (const item of e[c]) console.log(`      ${c.padEnd(5)} ${renderItem(c, item)}`);
    }
    if (!said) {
      console.log(`      ${C.dim}nothing observed${C.off}`);
    }
    if (blind.length) {
      console.log(`      ${C.amber}cannot see: ${blind.join(", ")}${C.off} ${C.dim}\u2014 silence there means nothing${C.off}`);
    }
    console.log("");
  }
  return EXIT.clean;
}
async function cmdIndex({ flags } = {}) {
  const index = await openIndex(flags || {});
  const m = index.manifest();
  if (!m) {
    console.log(`
  ${C.amber}No index built yet.${C.off}`);
    console.log(`  ${C.dim}\`npm run index:build\` populates it. Without one, nothing else here can answer anything.${C.off}
`);
    return EXIT.clean;
  }
  console.log(`
  ${C.bold}the behavioural index${C.off}
`);
  console.log(`  packages    ${m.packages.toLocaleString()}`);
  console.log(`  versions    ${m.versions.toLocaleString()}`);
  console.log(`  watched by  ${m.strategies.join(", ") || C.dim + "nothing" + C.off}`);
  console.log(`  revision    ${m.revision}`);
  console.log(`  built       ${C.dim}${m.generatedAt}${C.off}`);
  if (m.note) console.log(`  ${C.dim}${m.note}${C.off}`);
  console.log("");
  return EXIT.clean;
}
var USAGE = `
  ${C.bold}apollo${C.off} ${C.dim}\u2014 your lockfile pins versions. This pins behaviour.${C.off}

    apollo lock                walk package-lock.json, write ${DEFAULT_FILE}
    apollo check               diff the tree against the committed lock
    apollo upgrade             what the versions bumped since a commit now do differently
    apollo explain <pkg>       what a package does, and who watched it
    apollo index               what the index holds

  ${C.dim}flags${C.off}
    --lockfile <path>            default package-lock.json
    --lock <path>                default ${DEFAULT_FILE}
    --out <path>                 where \`lock\` writes
    --dry-run                    \`lock\` prints what it would do
    --fail-on-unknown            \`check\` exits 2 when the index has gaps
    --index <url|path>           read a published index instead of a local one
    --against <rev>              \`upgrade\` compares the lockfile with this commit's (default HEAD)
    --watched <url|path>         \`upgrade\` reads watched release pairs from here

  ${C.dim}with no index of your own${C.off}
    apollo lock --index https://apollo-watch.vercel.app/index.json
    ${C.dim}1,589 packages somebody already ran. Most of your tree will come back${C.off}
    ${C.dim}unknown, because most of npm has never been watched. That is the answer.${C.off}

  ${C.dim}exit codes: 0 clean \xB7 1 drift \xB7 2 unknown \xB7 3 usage${C.off}
`;
var COMMANDS = { lock: cmdLock, check: cmdCheck, upgrade: cmdUpgrade, explain: cmdExplain, index: cmdIndex };
async function main(argv) {
  const { flags, rest } = parseArgs(argv);
  const command = rest.shift();
  if (!command || flags.help || command === "help") {
    console.log(USAGE);
    return command ? EXIT.clean : EXIT.usage;
  }
  const fn = COMMANDS[command];
  if (!fn) {
    console.error(`
  ${C.red}No command "${command}".${C.off}`);
    console.log(USAGE);
    return EXIT.usage;
  }
  return fn({ flags, rest });
}
if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`
  ${C.red}${e.message}${C.off}
`);
      process.exit(EXIT.usage);
    }
  );
}
module.exports = { main, parseArgs, EXIT, renderItem };
