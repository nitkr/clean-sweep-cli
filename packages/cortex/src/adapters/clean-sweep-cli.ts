import { RemediationBackend } from "../backend"
import type {
  ScanResult,
  RemediationPlan,
  CleanResult,
  VerifyResult,
  Finding,
  FindingType,
  Severity,
  BackendCapability,
} from "../types"
import { spawn } from "bun"

interface CleanSweepCLIResult {
  success: boolean
  data?: unknown
  error?: string
}

export class CleanSweepCLIAdapter extends RemediationBackend {
  readonly config = {
    name: "CleanSweepCLI",
    version: "1.0.0",
    capabilities: ["scan", "plan", "clean", "verify", "dry_run"] as BackendCapability[],
  }

  private readonly cliPath: string

  constructor(cliPath = "clean-sweep") {
    super()
    this.cliPath = cliPath
  }

  async scan(target: string): Promise<ScanResult> {
    const result = await this.run(["scan", target])
    return this.parseScanResult(result, target)
  }

  async plan(scanResults: ScanResult): Promise<RemediationPlan> {
    const result = await this.run(["plan", JSON.stringify(scanResults)])
    return this.parsePlanResult(result, scanResults.id)
  }

  async clean(plan: RemediationPlan, dryRun = false): Promise<CleanResult> {
    const args = dryRun ? ["clean", "--dry-run", JSON.stringify(plan)] : ["clean", JSON.stringify(plan)]
    const result = await this.run(args)
    return this.parseCleanResult(result, plan.id, dryRun)
  }

  async verify(cleanResults: CleanResult): Promise<VerifyResult> {
    const result = await this.run(["verify", JSON.stringify(cleanResults)])
    return this.parseVerifyResult(result, cleanResults.id)
  }

  private async run(args: string[]): Promise<CleanSweepCLIResult> {
    const proc = spawn({
      cmd: [this.cliPath, ...args],
      stdout: "pipe",
      stderr: "pipe",
    })

    const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
    const exitCode = await proc.exited

    if (exitCode !== 0) {
      return { success: false, error: stderr || `Exit code: ${exitCode}` }
    }

    try {
      const data = stdout.trim() ? JSON.parse(stdout) : {}
      return { success: true, data }
    } catch {
      return { success: true, data: stdout }
    }
  }

  private parseScanResult(result: CleanSweepCLIResult, target: string): ScanResult {
    const id = crypto.randomUUID()
    const timestamp = Date.now()

    if (!result.success || !result.data) {
      return {
        id,
        target,
        timestamp,
        findings: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, clean: 0 },
      }
    }

    const data = result.data as Record<string, unknown>
    const findings: Finding[] = (data.findings as Finding[]) ?? []

    return {
      id,
      target,
      timestamp,
      findings,
      summary: this.computeSummary(findings),
    }
  }

  private parsePlanResult(result: CleanSweepCLIResult, scanId: string): RemediationPlan {
    const id = crypto.randomUUID()

    if (!result.success || !result.data) {
      return {
        id,
        scanId,
        steps: [],
        estimatedDuration: 0,
        risks: [],
      }
    }

    const data = result.data as Record<string, unknown>
    return {
      id,
      scanId,
      steps: (data.steps as RemediationPlan["steps"]) ?? [],
      estimatedDuration: (data.estimatedDuration as number) ?? 0,
      risks: (data.risks as string[]) ?? [],
    }
  }

  private parseCleanResult(result: CleanSweepCLIResult, planId: string, dryRun: boolean): CleanResult {
    const id = crypto.randomUUID()
    const timestamp = Date.now()

    if (!result.success || !result.data) {
      return {
        id,
        planId,
        dryRun,
        timestamp,
        executedSteps: [],
        summary: { total: 0, succeeded: 0, failed: 0, skipped: 0 },
      }
    }

    const data = result.data as Record<string, unknown>
    const executedSteps = (data.executedSteps as CleanResult["executedSteps"]) ?? []

    return {
      id,
      planId,
      dryRun,
      timestamp,
      executedSteps,
      summary: this.computeCleanSummary(executedSteps),
    }
  }

  private parseVerifyResult(result: CleanSweepCLIResult, cleanId: string): VerifyResult {
    const id = crypto.randomUUID()
    const timestamp = Date.now()

    if (!result.success || !result.data) {
      return {
        id,
        cleanId,
        timestamp,
        verified: false,
        checks: [],
        report: { filesScanned: 0, threatsRemoved: 0, integrityRestored: false, hardeningApplied: false },
      }
    }

    const data = result.data as Record<string, unknown>
    return {
      id,
      cleanId,
      timestamp,
      verified: (data.verified as boolean) ?? false,
      checks: (data.checks as VerifyResult["checks"]) ?? [],
      report: (data.report as VerifyResult["report"]) ?? {
        filesScanned: 0,
        threatsRemoved: 0,
        integrityRestored: false,
        hardeningApplied: false,
      },
    }
  }

  private computeSummary(findings: Finding[]): ScanResult["summary"] {
    return {
      total: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      clean: findings.filter((f) => f.type === "clean").length,
    }
  }

  private computeCleanSummary(steps: CleanResult["executedSteps"]): CleanResult["summary"] {
    return {
      total: steps.length,
      succeeded: steps.filter((s) => s.status === "success").length,
      failed: steps.filter((s) => s.status === "failed").length,
      skipped: steps.filter((s) => s.status === "skipped").length,
    }
  }
}
