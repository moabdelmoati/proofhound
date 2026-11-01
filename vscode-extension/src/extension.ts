import { exec } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";

const COLLECTION = "proofhound";

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection(COLLECTION);
  output = vscode.window.createOutputChannel("ProofHound");
  context.subscriptions.push(diagnostics, output);

  context.subscriptions.push(
    vscode.commands.registerCommand("proofhound.analyzeCommit", () => run("analyze")),
    vscode.commands.registerCommand("proofhound.scanCommit", () => run("scan")),
    vscode.commands.registerCommand("proofhound.clearDiagnostics", () => diagnostics.clear()),
  );
}

export function deactivate(): void {
  diagnostics?.dispose();
  output?.dispose();
}

function run(mode: "analyze" | "scan"): void {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    vscode.window.showErrorMessage("ProofHound: open a folder (git repository) first.");
    return;
  }
  const root = folder.uri.fsPath;
  const cfg = vscode.workspace.getConfiguration("proofhound");
  const exe = cfg.get<string>("executable", "proofhound");
  const config = cfg.get<string>("config", "configs/default.yaml");
  const commit = cfg.get<string>("commit", "HEAD");

  const sarifPath = path.join(os.tmpdir(), `proofhound-${Date.now()}.sarif`);
  const args =
    mode === "analyze"
      ? ["analyze", "--repo", ".", "--commit", commit, "--config", config, "--sarif", sarifPath]
      : [
          "scan", "--repo", ".", "--commit", commit, "--config", config,
          "--agent", "multi", "--model", "local-harness", "--sarif", sarifPath,
        ];

  const title =
    mode === "analyze" ? "ProofHound: analyzing changed functions…" : "ProofHound: scanning & proving…";

  vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title, cancellable: false },
    () =>
      new Promise<void>((resolve) => {
        const cmd = quote([exe, ...args]);
        output.appendLine(`$ ${cmd}`);
        exec(cmd, { cwd: root, maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
          output.append(stdout);
          if (stderr) output.append(stderr);
          if (err && !fs.existsSync(sarifPath)) {
            vscode.window.showErrorMessage(
              `ProofHound failed: ${err.message}. See the ProofHound output channel.`,
            );
            output.show(true);
            resolve();
            return;
          }
          try {
            const count = loadSarif(sarifPath, root);
            vscode.window.showInformationMessage(
              `ProofHound: ${count} finding${count === 1 ? "" : "s"}.`,
            );
          } catch (e) {
            vscode.window.showErrorMessage(`ProofHound: could not read results: ${e}`);
            output.show(true);
          } finally {
            fs.promises.unlink(sarifPath).catch(() => undefined);
          }
          resolve();
        });
      }),
  );
}

function loadSarif(sarifPath: string, root: string): number {
  const doc = JSON.parse(fs.readFileSync(sarifPath, "utf8"));
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const r of doc.runs ?? []) {
    for (const result of r.results ?? []) {
      const loc = result.locations?.[0]?.physicalLocation;
      if (!loc) continue;
      const uri = loc.artifactLocation?.uri ?? "";
      const line = Math.max(0, (loc.region?.startLine ?? 1) - 1);
      const abs = path.isAbsolute(uri) ? uri : path.join(root, uri);

      const diag = new vscode.Diagnostic(
        new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER),
        result.message?.text ?? result.ruleId ?? "finding",
        toSeverity(result.level),
      );
      diag.source = "ProofHound";
      diag.code = result.ruleId;

      const list = byFile.get(abs) ?? [];
      list.push(diag);
      byFile.set(abs, list);
    }
  }

  diagnostics.clear();
  let total = 0;
  for (const [file, list] of byFile) {
    diagnostics.set(vscode.Uri.file(file), list);
    total += list.length;
  }
  return total;
}

function toSeverity(level: string | undefined): vscode.DiagnosticSeverity {
  switch (level) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function quote(parts: string[]): string {
  return parts.map((p) => (/[\s"]/.test(p) ? `"${p.replace(/"/g, '\\"')}"` : p)).join(" ");
}
