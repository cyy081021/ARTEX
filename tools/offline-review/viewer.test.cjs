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
    textContent: "", value: "", children: [], handlers: {}, hidden: false,
    addEventListener(name, handler) { this.handlers[name] = handler; },
    replaceChildren(fragment) { this.children = fragment?.children ?? []; },
    append(item) { this.children.push(item); },
    focus() { this.focused = true; },
  };
}

// Only enough DOM to drive the real inline script; browser layout is tested separately.
function viewer() {
  const elements = new Map(["file", "json-text", "show-json", "clear", "status", "record", "record-title", "history", "empty-history"]
    .map(id => [id, element()]));
  const get = id => elements.get(id);
  const window = element();
  let parseCalls = 0;
  const context = vm.createContext({
    window, TextDecoder, TextEncoder,
    document: { querySelector: selector => get(selector.slice(1)), createElement: element, createDocumentFragment: element },
  });
  const json = vm.runInContext("JSON", context);
  const parse = json.parse;
  json.parse = (...args) => { parseCalls++; return parse(...args); };
  vm.runInContext(script, context);
  function edit(text) {
    get("json-text").value = text;
    get("json-text").handlers.input();
  }
  const show = () => get("show-json").handlers.click();
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
  return { get, window, choose, load, edit, show, parseCount: () => parseCalls, rows, assertEmpty };
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

test("editing clears the previous file without parsing; Show consumes and safely displays the draft", async () => {
  const v = viewer();
  await v.load(archive("原档案", [{ reason: "旧记录" }]));
  const literal = "<em>文字 & 标记</em>";
  const draft = archive(literal, [{ reason: literal }, {}, { reason: " " }]);
  const previous = v.parseCount();
  v.edit("{");
  v.edit(draft);
  v.assertEmpty();
  assert.equal(v.parseCount(), previous);
  assert.equal(v.get("json-text").value, draft);
  await v.show();
  assert.equal(v.parseCount(), previous + 1);
  assert.equal(v.get("json-text").value, "");
  assert.equal(v.get("record").hidden, false);
  assert.equal(v.get("record-title").textContent, literal);
  assert.deepEqual(v.rows(), [literal, "未提供原因", "未提供原因"]);
});

test("text counts UTF-8 bytes including the BOM and handles one BOM just like a file", async () => {
  const v = viewer();
  const limit = 256 * 1024;
  const title = "界".repeat(80_000);
  const base = "\uFEFF" + archive(title);
  const exact = base + " ".repeat(limit - encoder.encode(base).length);
  assert.ok(exact.length + 1 < limit);
  v.edit(exact);
  await v.show();
  assert.equal(v.get("record-title").textContent.length, title.length);
  assert.equal(v.get("record").hidden, false);
  v.edit(exact + " ");
  await v.show();
  v.assertEmpty();
  assert.equal(v.get("json-text").value, "");
  const twoBOMs = "\uFEFF\uFEFF" + archive("仅一个 BOM");
  await v.load(twoBOMs);
  v.assertEmpty();
  v.edit(twoBOMs);
  await v.show();
  v.assertEmpty();
});

test("invalid text is consumed and failed validation never leaves partial rows", async () => {
  const v = viewer();
  const rows = Array.from({ length: 500 }, () => ({ reason: "测试" }));
  const valid = archive("边界", rows);
  for (const bad of ["{", JSON.stringify({ title: "额外字段", history: [], extra: true }),
    archive("无效条目", [{ reason: "前一行" }, null]), archive("过多", [...rows, {}])]) {
    v.edit(valid);
    await v.show();
    assert.equal(v.rows().length, 500);
    v.edit(bad);
    await v.show();
    v.assertEmpty();
    assert.equal(v.get("json-text").value, "");
    assert.equal(v.get("clear").disabled, true);
  }
});

test("a later file, clear or page exit discards an unsubmitted draft", async () => {
  for (const action of ["file", "clear", "pagehide"]) {
    const v = viewer();
    v.edit(archive("草稿", [{ reason: "不会显示" }]));
    if (action === "file") {
      const deferred = Promise.withResolvers();
      const pending = v.choose({ size: 40, arrayBuffer: () => deferred.promise });
      assert.equal(v.get("json-text").value, "");
      v.assertEmpty();
      deferred.resolve(encoder.encode(archive("后选文件")));
      await pending;
      assert.equal(v.get("record-title").textContent, "后选文件");
    } else {
      if (action === "clear") v.get("clear").handlers.click();
      else v.window.handlers.pagehide();
      v.assertEmpty();
    }
    assert.equal(v.get("json-text").value, "");
    assert.equal(v.get("show-json").disabled, true);
  }
});

test("a late file read cannot replace a newer draft, shown text or text error", async () => {
  for (const completion of ["resolve", "reject"]) {
    for (const next of ["draft", "shown", "invalid"]) {
      const v = viewer();
      const deferred = Promise.withResolvers();
      const pending = v.choose({ size: 55, arrayBuffer: () => deferred.promise });
      const draft = next === "invalid" ? "{" : archive("新文本", [{ reason: "新原因" }]);
      v.edit(draft);
      if (next !== "draft") await v.show();
      const message = v.get("status").textContent;
      if (completion === "resolve") deferred.resolve(encoder.encode(archive("过期文件")));
      else deferred.reject(new Error("synthetic file error"));
      await pending;
      assert.equal(v.get("status").textContent, message);
      assert.equal(v.get("json-text").value, next === "draft" ? draft : "");
      if (next === "shown") {
        assert.equal(v.get("record-title").textContent, "新文本");
        assert.deepEqual(v.rows(), ["新原因"]);
      } else {
        v.assertEmpty();
      }
    }
  }
});
