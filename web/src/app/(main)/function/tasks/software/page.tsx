"use client";

import * as React from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldLabel } from "@/components/ui/field";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { http } from "@/lib/api";
import {
  downloadFile,
  readMaterial,
  sceneLabels,
  softwareReport,
  stateLabels,
  type EvidenceState,
  type Material,
  type SoftwareRecord,
} from "@/lib/software-dossier";

const selectClass = "w-full min-w-0";
function bytes(f: Material) {
  return Uint8Array.from(atob(f.data), (c) => c.charCodeAt(0));
}

export default function SoftwareDossierPage() {
  const [record, setRecord] = React.useState<SoftwareRecord | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [selected, setSelected] = React.useState(-1);
  const [line, setLine] = React.useState("");
  const [subject, setSubject] = React.useState("");
  const [text, setText] = React.useState("");
  const [state, setState] = React.useState<EvidenceState>("source");
  const [search, setSearch] = React.useState("");
  const [lineFocus, setLineFocus] = React.useState(0);
  const [declared, setDeclared] = React.useState("");
  const [tools, setTools] = React.useState<Record<string, boolean> | null>(null);
  React.useEffect(() => {
    void http<Record<string, boolean>>("/software-dossiers/environment")
      .then(setTools)
      .catch(() => setTools(null));
  }, []);
  const picker = React.useRef<HTMLInputElement>(null);
  const reload = React.useCallback(async () => {
    const id = new URLSearchParams(window.location.search).get("id");
    if (!id) throw new Error("缺少档案编号");
    const value = await http<SoftwareRecord>("/software-dossiers/" + encodeURIComponent(id));
    setRecord(value);
    setError("");
  }, []);
  React.useEffect(() => {
    void reload().catch((e) => setError(e.message));
  }, [reload]);
  async function act(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const endpoint = "/software-dossiers/" + (record?.id ?? "");
  async function append(p: object) {
    const changed = await http<SoftwareRecord>(endpoint, {
      method: "PATCH",
      body: JSON.stringify({ revision: record?.revision, ...p }),
    });
    setRecord(changed);
  }
  const back = (
    <Link className="text-sm text-primary underline" href="/function/tasks/">
      返回任务列表
    </Link>
  );
  if (!record)
    return (
      <main className="grid gap-4 p-6">
        {back}
        <p role="status">{error || "正在读取软件档案…"}</p>
        {error && (
          <Button variant="outline" onClick={() => void act(reload)}>
            重试
          </Button>
        )}
      </main>
    );
  const d = record.dossier,
    f = d.files[selected];
  const report = softwareReport(record);
  const preview =
    f?.format === "文本" && f.data.length < 2_800_000 ? new TextDecoder().decode(bytes(f)).split(/\r?\n/) : null;
  const focus = Math.max(0, lineFocus - 1);
  const start = focus > 12 ? focus - 12 : 0;
  const visibleFiles = d.files
    .map((m, i) => ({ m, i }))
    .filter(({ m }) => m.name.toLowerCase().includes(search.toLowerCase()));
  return (
    <main className="mx-auto grid w-full max-w-5xl gap-5 p-4 md:p-6">
      {back}
      <header className="grid gap-2">
        <div>
          <Badge variant="secondary">{sceneLabels[d.scenario]}</Badge>
        </div>
        <h1 className="break-all text-2xl font-semibold">{d.name}</h1>
        <p>{d.goal}</p>
        <dl className="grid gap-1 break-all text-sm text-muted-foreground">
          <div>来源　{d.origin || "本地上传"}</div>
          <div>声明版本　{d.version || "未提供"}</div>
          {d.commit && <div>基线提交　{d.commit}</div>}
          {d.snapshot && <div>源码快照 SHA-256　{d.snapshot}</div>}
          {d.platform && <div>声明平台　{d.platform}</div>}
        </dl>
      </header>
      {error && (
        <p role="alert" className="text-destructive">
          {error}{" "}
          <Button variant="link" onClick={() => void act(reload)}>
            刷新档案
          </Button>
        </p>
      )}
      <Card>
        <CardHeader>
          <CardTitle>材料与来源</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3">
          <Field>
            <FieldLabel htmlFor="file-search">查找材料</FieldLabel>
            <Input
              id="file-search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="相对路径或包名"
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="dossier-file">文件（{visibleFiles.length}）</FieldLabel>
            <NativeSelect
              className={selectClass}
              id="dossier-file"
              value={selected}
              onChange={(e) => {
                setSelected(Number(e.target.value));
                setLineFocus(0);
                setLine("");
              }}
            >
              <NativeSelectOption value={-1}>选择材料</NativeSelectOption>
              {visibleFiles.map(({ m, i }) => (
                <NativeSelectOption key={i} value={i}>
                  {m.name} · {m.sha256?.slice(0, 12)}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </Field>
          {f && (
            <div className="grid min-w-0 gap-2 break-all text-sm">
              <p>
                {f.name} · {f.format} · SHA-256 {f.sha256}
              </p>
              {f.parent && <p>父包 SHA-256　{f.parent}</p>}
              {f.kind === "evidence" && <p>材料声明的快照或发行包　{f.subject || "未核对"}</p>}
              {preview && (
                <pre tabIndex={0} className="max-h-60 overflow-auto rounded-md bg-muted p-3">
                  {preview
                    .slice(start, start + 80)
                    .map((s, i) => start + i + 1 + "  " + s)
                    .join("\n")}
                </pre>
              )}
              <Button
                className="justify-self-start"
                variant="outline"
                onClick={() => downloadFile(f.name.split("/").pop()!, bytes(f), "application/octet-stream")}
              >
                下载原材料
              </Button>
            </div>
          )}
          <input
            ref={picker}
            hidden
            type="file"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              void act(async () => {
                const m = await readMaterial(file, file.name, "evidence");
                m.subject = declared.trim().toLowerCase();
                await append({ files: [m] });
                setDeclared("");
              }).finally(() => {
                if (picker.current) picker.current.value = "";
              });
            }}
          />
          <Field>
            <FieldLabel htmlFor="evidence-source-hash">待附证据声明的快照或包 SHA-256（可选）</FieldLabel>
            <Input id="evidence-source-hash" value={declared} onChange={(e) => setDeclared(e.target.value)} />
          </Field>
          <Button
            className="justify-self-start"
            disabled={busy}
            variant="outline"
            onClick={() => picker.current?.click()}
          >
            附加已有证据
          </Button>
          <details className="text-sm text-muted-foreground">
            <summary className="cursor-pointer">本机工具可见性</summary>
            <p>
              {tools
                ? Object.entries(tools)
                    .map(([k, v]) => k + " " + (v ? "PATH 可见" : "未在 PATH 检出"))
                    .join(" · ")
                : "未取得检查结果"}
            </p>
            <p>这里只检查宿主机 PATH。容器、运行授权及实际工具运行情况需另有记录。</p>
          </details>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>观察与依据</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          {!d.notes.length && <p className="text-sm text-muted-foreground">尚无已登记的审阅结论。</p>}
          {d.notes.map((n, i) => (
            <article className="grid gap-1 border-b pb-3 text-sm" key={i}>
              <div>
                <Badge variant="secondary">{stateLabels[n.state]}</Badge>
              </div>
              <p className="whitespace-pre-wrap">{n.text}</p>
              <p className="break-all text-muted-foreground">适用版本　{n.subject || "未核对"}</p>
              {n.file && (
                <Button
                  className="h-auto justify-self-start whitespace-normal break-all p-0"
                  variant="link"
                  onClick={() => {
                    setSearch("");
                    setSelected(
                      d.files.findIndex(
                        (m) =>
                          m.name === n.file &&
                          m.sha256 === n.sha256 &&
                          (!n.subject ||
                            (m.kind === "source"
                              ? d.snapshot
                              : m.kind === "component"
                                ? m.parent
                                : m.kind === "evidence"
                                  ? m.subject
                                  : m.sha256) === n.subject),
                      ),
                    );
                    setLineFocus(n.line || 1);
                    document.getElementById("dossier-file")?.focus();
                  }}
                >
                  {n.file}
                  {n.line ? " · 第 " + n.line + " 行" : ""} · {n.sha256?.slice(0, 12)}
                </Button>
              )}
            </article>
          ))}
          <form
            className="grid gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              void act(async () => {
                if (!f && state !== "unresolved") throw new Error("请先在材料栏选择引用文件");
                await append({
                  notes: [{ state, text, subject, file: f?.name, sha256: f?.sha256, line: line ? Number(line) : 0 }],
                });
                setText("");
                setLine("");
              });
            }}
          >
            <Field>
              <FieldLabel htmlFor="note-type">记录类别</FieldLabel>
              <NativeSelect
                id="note-type"
                className={selectClass}
                value={state}
                onChange={(e) => setState(e.target.value as EvidenceState)}
              >
                {Object.entries(stateLabels).map(([key, v]) => (
                  <NativeSelectOption key={key} value={key}>
                    {v}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            </Field>
            <Field>
              <FieldLabel htmlFor="note-subject">适用版本</FieldLabel>
              <NativeSelect
                id="note-subject"
                className={selectClass}
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
              >
                <NativeSelectOption value="">对应关系未核对</NativeSelectOption>
                {d.snapshot && (
                  <NativeSelectOption value={d.snapshot}>当前源码快照 · {d.snapshot.slice(0, 12)}</NativeSelectOption>
                )}
                {d.files
                  .filter((m) => m.kind === "package")
                  .map((m, i) => (
                    <NativeSelectOption key={i} value={m.sha256}>
                      {m.name} · {m.sha256?.slice(0, 12)}
                    </NativeSelectOption>
                  ))}
              </NativeSelect>
            </Field>
            <Field>
              <FieldLabel htmlFor="note-text">观察或待确认事项</FieldLabel>
              <Textarea required id="note-text" value={text} onChange={(e) => setText(e.target.value)} />
            </Field>
            {f && (
              <p className="text-sm">
                引用材料　{f.name} · {f.sha256?.slice(0, 12)}
              </p>
            )}
            {f?.format === "文本" && (
              <Field>
                <FieldLabel htmlFor="note-line">引用行号（可选）</FieldLabel>
                <Input id="note-line" type="number" min={1} value={line} onChange={(e) => setLine(e.target.value)} />
              </Field>
            )}
            <Button className="justify-self-start" disabled={busy} type="submit">
              保存观察
            </Button>
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>报告与归档</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          <Button
            variant="outline"
            onClick={() => downloadFile("software-report-" + record.id + ".txt", report, "text/plain;charset=utf-8")}
          >
            导出审阅报告
          </Button>
          <Button
            variant="outline"
            disabled={busy}
            onClick={() =>
              void act(async () => {
                const archive = await http<unknown>(endpoint + "/archive");
                downloadFile("software-" + record.id + ".json", JSON.stringify(archive), "application/json");
              })
            }
          >
            导出完整归档
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
