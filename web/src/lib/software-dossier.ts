export type SoftwareScenario = "open_source_software" | "closed_source_software";
export type SceneChoice = "auto" | "web" | "reverse" | SoftwareScenario;
export const sceneLabels = {
  auto: "自动识别",
  web: "Web",
  reverse: "逆向分析",
  open_source_software: "开源软件",
  closed_source_software: "闭源软件",
} as const;

export const stateLabels = {
  source: "源码观察",
  observed: "运行记录",
  contradiction: "反证",
  unresolved: "待确认",
} as const;
export type EvidenceState = keyof typeof stateLabels;
export type Material = {
  name: string;
  kind: string;
  data: string;
  sha256?: string;
  format?: string;
  parent?: string;
  subject?: string;
};
export type Observation = {
  state: EvidenceState;
  text: string;
  file?: string;
  sha256?: string;
  line?: number;
  subject?: string;
};
export type SoftwareRecord = {
  id: string;
  revision: number;
  dossier: {
    scenario: SoftwareScenario;
    name: string;
    goal: string;
    origin?: string;
    version?: string;
    commit?: string;
    snapshot?: string;
    platform?: string;
    files: Material[];
    notes: Observation[];
  };
};
export type Summary = { id: string; name: string; scenario: SoftwareScenario; revision: number };
export const maxSize = 32 * 1024 * 1024;
export function inferScene(choice: SceneChoice, object: string): SceneChoice {
  if (choice !== "auto") return choice;
  if (/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/i.test(object.trim())) return "open_source_software";
  if (/\.(?:exe|dll|msi|apk|ipa|elf|so|dylib|deb|rpm|dmg)$/i.test(object.trim())) return "closed_source_software";
  return "auto";
}

export async function readMaterial(file: File, name: string, kind: string): Promise<Material> {
  if (file.size > maxSize) throw new Error("单份档案材料总量限 32 MiB");
  const data = await new Promise<string>((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(new Error("读取材料失败"));
    r.onload = () => resolve(String(r.result).split(",")[1] ?? "");
    r.readAsDataURL(file);
  });
  return { name, kind, data };
}

export function downloadFile(name: string, content: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function softwareReport({ id, revision, dossier: d }: SoftwareRecord) {
  const lines = [
    d.name,
    sceneLabels[d.scenario],
    d.goal,
    "",
    "档案 " + id + " · 修订 " + revision,
    "来源 " + (d.origin || "本地上传"),
    "声明版本 " + (d.version || "未提供"),
    "提交 " + (d.commit || "未提供"),
    "源码快照 " + (d.snapshot || "无"),
    "声明平台 " + (d.platform || "未提供"),
    "",
    "材料",
  ];
  for (const f of d.files)
    lines.push(
      [
        f.name,
        f.format,
        f.sha256,
        f.parent && "父包 " + f.parent,
        f.kind === "evidence" && "声明关联 " + (f.subject || "未核对"),
      ]
        .filter(Boolean)
        .join(" · "),
    );
  lines.push("", "观察与依据");
  for (const n of d.notes)
    lines.push(
      [
        stateLabels[n.state],
        n.text,
        n.file,
        n.line && "第 " + n.line + " 行",
        n.sha256,
        "适用版本 " + (n.subject || "未核对"),
      ]
        .filter(Boolean)
        .join(" · "),
    );
  if (!d.notes.length) lines.push("尚无已登记的审阅结论。");
  return lines.join("\n");
}
