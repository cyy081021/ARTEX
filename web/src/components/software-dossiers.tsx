"use client";

import * as React from "react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { http } from "@/lib/api";
import {
  maxSize,
  readMaterial,
  sceneLabels,
  type SceneChoice,
  type SoftwareScenario,
  type Summary,
} from "@/lib/software-dossier";
import { toast } from "sonner";

export function ScenarioPicker({
  choice,
  object,
  onChoice,
  onObject,
}: {
  choice: SceneChoice;
  object: string;
  onChoice: (s: SceneChoice) => void;
  onObject: (s: string) => void;
}) {
  return (
    <div className="grid gap-3 border-b px-6 py-4 sm:grid-cols-[10rem_1fr]">
      <Field>
        <FieldLabel htmlFor="task-scene">任务场景</FieldLabel>
        <NativeSelect
          id="task-scene"
          value={choice}
          onChange={(e) => onChoice(e.target.value as SceneChoice)}
          className="w-full"
        >
          {Object.entries(sceneLabels).map(([v, label]) => (
            <NativeSelectOption key={v} value={v}>
              {label}
            </NativeSelectOption>
          ))}
        </NativeSelect>
      </Field>
      <Field>
        <FieldLabel htmlFor="software-object">对象或仓库</FieldLabel>
        <Input
          id="software-object"
          value={object}
          onChange={(e) => onObject(e.target.value)}
          placeholder="仓库地址、发行包名称或站点"
        />
      </Field>
    </div>
  );
}

export function SoftwareCreateForm({
  scene,
  object,
  initialFiles,
  goal,
  setGoal,
  onDone,
  onBusy,
}: {
  scene: SoftwareScenario;
  object: string;
  initialFiles: File[];
  goal: string;
  setGoal: (s: string) => void;
  onDone: (id: string) => void;
  onBusy: (v: boolean) => void;
}) {
  const [files, setFiles] = React.useState<File[]>(initialFiles);
  const [packages, setPackages] = React.useState<File[]>([]);
  const [version, setVersion] = React.useState("");
  const [commit, setCommit] = React.useState("");
  const [platform, setPlatform] = React.useState("");
  const [error, setError] = React.useState("");
  const requestId = React.useRef("");
  const inFlight = React.useRef(false);
  const open = scene === "open_source_software";
  const folder = React.useRef<HTMLInputElement>(null);
  React.useEffect(() => {
    folder.current?.setAttribute("webkitdirectory", "");
  }, [open]);
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (inFlight.current) return;
    inFlight.current = true;
    onBusy(true);
    setError("");
    try {
      const selected = files.filter((f) => !f.webkitRelativePath.split("/").includes(".git"));
      const all = [...selected, ...packages];
      if (all.length > 4096 || all.reduce((s, f) => s + f.size, 0) > maxSize)
        throw new Error("每份档案最多 4096 个文件，材料总量限 32 MiB。");
      if (!goal.trim()) throw new Error("请填写审阅目的。");
      const fetchRepository =
        open && selected.length === 0 && /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/.test(object.trim());
      if (!selected.length && !fetchRepository)
        throw new Error(open ? "请选择源码目录、源码 ZIP 或填写公共 GitHub 仓库地址。" : "请选择发行包。");
      const materials = [];
      for (const f of selected) {
        const name = f.webkitRelativePath ? f.webkitRelativePath.split("/").slice(1).join("/") : f.name;
        materials.push(
          await readMaterial(
            f,
            name,
            open ? (f.webkitRelativePath || !/\.zip$/i.test(f.name) ? "source" : "source_archive") : "package",
          ),
        );
      }
      for (const f of packages) materials.push(await readMaterial(f, f.name, "package"));
      if (!requestId.current) {
        const bytes = crypto.getRandomValues(new Uint8Array(16));
        bytes[6] = (bytes[6] & 15) | 64;
        bytes[8] = (bytes[8] & 63) | 128;
        const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
        requestId.current = [
          hex.slice(0, 8),
          hex.slice(8, 12),
          hex.slice(12, 16),
          hex.slice(16, 20),
          hex.slice(20),
        ].join("-");
      }
      const response = await http<{ id: string }>("/tasks", {
        method: "POST",
        body: JSON.stringify({
          scenario: scene,
          software: {
            id: requestId.current,
            name: object.trim() || files[0]?.webkitRelativePath.split("/")[0] || files[0]?.name,
            goal,
            origin: object.trim(),
            version,
            commit,
            platform,
            fetch_repository: fetchRepository,
            files: materials,
          },
        }),
      });
      onDone(response.id);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      inFlight.current = false;
      onBusy(false);
    }
  }
  return (
    <form id="software-create" onSubmit={submit} className="grid content-start gap-5 overflow-y-auto p-6">
      <Field>
        <FieldLabel htmlFor="software-goal">审阅目的</FieldLabel>
        <Textarea required id="software-goal" value={goal} onChange={(e) => setGoal(e.target.value)} />
      </Field>
      <Field>
        <FieldLabel htmlFor="software-files">{open ? "源码文件或 ZIP" : "发行包"}</FieldLabel>
        <Input id="software-files" type="file" multiple onChange={(e) => setFiles(Array.from(e.target.files ?? []))} />
        <FieldDescription>
          {open ? "公共 GitHub 仓库可直接按版本生成快照，也可上传本地文件。" : "同名发行包由 SHA-256 区分。"}{" "}
          单份档案上限 32 MiB。
        </FieldDescription>
      </Field>
      {open && (
        <Field>
          <FieldLabel htmlFor="source-folder">或选择本地源码目录</FieldLabel>
          <Input
            ref={folder}
            id="source-folder"
            type="file"
            multiple
            onChange={(e) => setFiles(Array.from(e.target.files ?? []))}
          />
        </Field>
      )}
      {!!files.length && <span className="text-sm text-muted-foreground">已选择 {files.length} 个文件</span>}
      <Field>
        <FieldLabel htmlFor="software-version">{open ? "标签、分支或提交（可选）" : "产品版本（可选）"}</FieldLabel>
        <Input id="software-version" value={version} onChange={(e) => setVersion(e.target.value)} />
      </Field>
      {open ? (
        <>
          <Field>
            <FieldLabel htmlFor="software-commit">本地源码的基线提交（可选）</FieldLabel>
            <Input id="software-commit" value={commit} onChange={(e) => setCommit(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="software-release">随源码附带的发行包（可选）</FieldLabel>
            <Input
              id="software-release"
              type="file"
              multiple
              onChange={(e) => setPackages(Array.from(e.target.files ?? []))}
            />
          </Field>
        </>
      ) : (
        <Field>
          <FieldLabel htmlFor="software-platform">声明平台与架构（可选）</FieldLabel>
          <Input id="software-platform" value={platform} onChange={(e) => setPlatform(e.target.value)} />
        </Field>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}

export function SoftwareList({ query, onCount }: { query: string; onCount: (count: number) => void }) {
  const [rows, setRows] = React.useState<Summary[]>([]);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const picker = React.useRef<HTMLInputElement>(null);
  const refresh = React.useCallback(async () => {
    const data = await http<Summary[]>("/software-dossiers");
    setRows(data);
    onCount(data.length);
    setError("");
  }, [onCount]);
  React.useEffect(() => {
    void refresh().catch((e) => setError(e.message));
  }, [refresh]);
  async function restore(f?: File) {
    if (!f) return;
    setBusy(true);
    setError("");
    try {
      if (f.size > 56 * 1024 * 1024) throw new Error("归档超过上限");
      await http("/software-dossiers/restore", { method: "POST", body: await f.text() });
      await refresh();
      toast.success("软件档案已恢复");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
      if (picker.current) picker.current.value = "";
    }
  }
  return (
    <section aria-label="软件档案" className="mx-4 grid gap-2 lg:mx-6">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">软件档案</h3>
        <input ref={picker} type="file" hidden accept=".json" onChange={(e) => void restore(e.target.files?.[0])} />
        <Button size="sm" variant="ghost" disabled={busy} onClick={() => picker.current?.click()}>
          {busy ? "恢复中…" : "恢复软件归档"}
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}{" "}
          <Button size="sm" variant="link" onClick={() => void refresh().catch((e) => setError(e.message))}>
            重试
          </Button>
        </p>
      )}
      {rows
        .filter((row) =>
          (row.name + " " + row.id + " " + sceneLabels[row.scenario])
            .toLowerCase()
            .includes(query.trim().toLowerCase()),
        )
        .map((row) => (
          <Link
            className="flex min-h-11 items-center gap-3 rounded-md border px-3 hover:bg-muted"
            key={row.id}
            href={"/function/tasks/software/?id=" + row.id}
          >
            <Badge variant="secondary">{sceneLabels[row.scenario]}</Badge>
            <span className="min-w-0 flex-1 truncate">{row.name}</span>
            <span className="text-xs text-muted-foreground">修订 {row.revision}</span>
          </Link>
        ))}
    </section>
  );
}
