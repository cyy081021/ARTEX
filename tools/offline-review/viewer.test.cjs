const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const html = readFileSync(path.join(__dirname, "index.html"), "utf8").replace(/\r\n/g, "\n");
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const encoder = new TextEncoder();
const archive = (title, history = []) => JSON.stringify({ title, history });

function element() {
  return {
    textContent: "", children: [], handlers: {}, hidden: false,
    addEventListener(name, handler) { this.handlers[name] = handler; },
    replaceChildren(fragment) { this.children = fragment?.children ?? []; },
    append(item) { this.children.push(item); },
    focus() { this.focused = true; },
  };
}

// Only enough DOM to drive the real inline script; browser layout is tested separately.
function viewer() {
  const elements = new Map(["file", "clear", "status", "record", "record-title", "history", "empty-history"]
    .map(id => [id, element()]));
  const get = id => elements.get(id);
  const window = element();
  vm.runInNewContext(script, {
    window, TextDecoder,
    document: { querySelector: selector => get(selector.slice(1)), createElement: element, createDocumentFragment: element },
  });
  function choose(file) {
    get("file").files = file ? [file] : [];
    return get("file").handlers.change();
  }
  const load = data => {
    const bytes = typeof data === "string" ? encoder.encode(data) : data;
    return choose({ size: bytes.byteLength, arrayBuffer: async () => bytes });
  };
  const rows = () => get("history").children.map(item => item.textContent);
  function assertEmpty() {
    assert.equal(get("record").hidden, true);
    assert.equal(get("record-title").textContent, "");
    assert.deepEqual(rows(), []);
  }
  return { get, window, choose, load, rows, assertEmpty };
}

test("the standalone page authorizes its exact inline script and disallows connections", () => {
  const digest = createHash("sha256").update(script).digest("base64");
  assert.ok(html.includes(`script-src 'sha256-${digest}'`));
  assert.ok(html.includes("default-src 'none'"));
  assert.ok(html.includes("connect-src 'none'"));
});

test("titles and review reasons are text; empty reasons retain their position", async () => {
  const v = viewer();
  const literal = "<em>示例</em>";
  await v.load(archive(literal, [{ reason: literal }, {}, { reason: null }, { reason: "  " }]));
  assert.equal(v.get("record-title").textContent, literal);
  assert.deepEqual(v.rows(), [literal, "未提供原因", "未提供原因", "未提供原因"]);
  assert.equal(v.get("record").hidden, false);
  await v.load(archive("空历史"));
  assert.deepEqual(v.rows(), []);
  assert.equal(v.get("empty-history").hidden, false);
});

test("invalid files or unknown fields reject the entire file and clear the previous view", async () => {
  const v = viewer();
  for (const bad of ["", "{", new Uint8Array([0xff]), "null", "[]", "{}",
    archive("  "), '{"title":"示例","history":{},"extra":1}', '{"title":"示例","history":[],"extra":1}',
    archive("示例", [null]), archive("示例", [{ reason: 9 }]), archive("示例", [{ reason: "文本", extra: 1 }])]) {
    await v.load(archive("原档案", [{ reason: "原记录" }]));
    await v.load(bad);
    v.assertEmpty();
    assert.equal(v.get("clear").disabled, true);
  }
});

test("byte and row limits accept the boundary and reject overflow", async () => {
  const v = viewer();
  const limit = 256 * 1024;
  const base = archive("上限");
  await v.load(base + " ".repeat(limit - encoder.encode(base).length));
  assert.equal(v.get("record-title").textContent, "上限");
  let reads = 0;
  await v.choose({ size: limit + 1, arrayBuffer() { reads++; } });
  v.assertEmpty();
  assert.equal(reads, 0);
  await v.load(archive("条数", Array.from({ length: 500 }, () => ({}))));
  assert.equal(v.rows().length, 500);
  await v.load(archive("条数", Array.from({ length: 501 }, () => ({}))));
  v.assertEmpty();
});

test("late successes and failures cannot overwrite a replacement, a clear or a page exit", async () => {
  for (const settle of ["resolve", "reject"]) {
    for (const action of ["replace", "bad-file", "clear", "pagehide"]) {
      const v = viewer();
      await v.load(archive("前一份", [{ reason: "旧记录" }]));
      const deferred = Promise.withResolvers();
      const pending = v.choose({ size: 60, arrayBuffer: () => deferred.promise });
      v.assertEmpty();
      if (action === "replace") await v.load(archive("当前档案", [{ reason: "当前记录" }]));
      if (action === "bad-file") await v.load("{");
      if (action === "clear") v.get("clear").handlers.click();
      if (action === "pagehide") v.window.handlers.pagehide();
      const message = v.get("status").textContent;
      if (settle === "resolve") deferred.resolve(encoder.encode(archive("晚到记录")));
      else deferred.reject(new Error("synthetic read failure"));
      await pending;
      assert.equal(v.get("status").textContent, message);
      if (action === "replace") {
        assert.equal(v.get("record-title").textContent, "当前档案");
        assert.deepEqual(v.rows(), ["当前记录"]);
      } else {
        v.assertEmpty();
      }
    }
  }
});
