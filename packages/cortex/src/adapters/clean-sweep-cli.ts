import { RemediationBackend } from "../backend"
import type {
  ScanResult,
  RemediationPlan,
  CleanResult,
  VerifyResult,
  Finding,
  FindingType,
  BackendCapability,
  RemediationAction,
} from "../types"
import { spawn } from "bun"

export class CleanSweepCLIAdapter extends RemediationBackend {
  readonly config = {
    name: "CleanSweepCLI",
    version: "1.0.0",
    capabilities: ["scan", "plan", "clean", "verify", "dry_run"] as BackendCapability[],
  }

  private readonly cliPath: string

  constructor(cliPath = "./bin/clean-sweep") {
    super()
    this.cliPath = cliPath
  }

  async scan(target: string): Promise<ScanResult> {
    const result = await this.run(["scan", "--path", target])
    return this.parseScanResult(result, target)
  }

  async plan(scanResults: ScanResult): Promise<RemediationPlan> {
    const id = crypto.randomUUID()
    const steps = this.generateSteps(scanResults.findings)
    return {
      id,
      scanId: scanResults.id,
      steps,
      estimatedDuration: steps.length * 30,
      risks: this.assessRisks(steps),
    }
  }

  async clean(plan: RemediationPlan, dryRun = false): Promise<CleanResult> {
    const id = crypto.randomUUID()
    const timestamp = Date.now()
    const executedSteps = []

    for (const step of plan.steps) {
      if (dryRun) {
        executedSteps.push({
          stepId: step.id,
          status: "skipped" as const,
          message: `[DRY-RUN] Would execute: ${step.action} on ${step.target}`,
        })
        continue
      }

      const result = await this.executeStep(step)
      executedSteps.push(result)
    }

    return {
      id,
      planId: plan.id,
      dryRun,
      timestamp,
      executedSteps,
      summary: {
        total: executedSteps.length,
        succeeded: executedSteps.filter((s) => s.status === "success").length,
        failed: executedSteps.filter((s) => s.status === "failed").length,
        skipped: executedSteps.filter((s) => s.status === "skipped").length,
      },
    }
  }

  async verify(cleanResults: CleanResult): Promise<VerifyResult> {
    const id = crypto.randomUUID()
    const timestamp = Date.now()

    const [statusResult, hardenResult, permissionsResult] = await Promise.all([
      this.run(["status"]),
      this.run(["harden:check"]),
      this.run(["permissions:check"]),
    ])

    const checks = []

    checks.push({
      name: "system_status",
      passed: statusResult.success,
      details: statusResult.success ? "System status OK" : statusResult.error,
    })

    checks.push({
      name: "hardening",
      passed: hardenResult.success,
      details: hardenResult.success ? "Hardening checks passed" : hardenResult.error,
    })

    checks.push({
      name: "permissions",
      passed: permissionsResult.success,
      details: permissionsResult.success ? "Permissions checks passed" : permissionsResult.error,
    })

    const verified = checks.every((c) => c.passed)

    return {
      id,
      cleanId: cleanResults.id,
      timestamp,
      verified,
      checks,
      report: {
        filesScanned: 0,
        threatsRemoved: cleanResults.summary.succeeded,
        integrityRestored: verified,
        hardeningApplied: checks.find((c) => c.name === "hardening")?.passed ?? false,
      },
    }
  }

  private async run(args: string[]): Promise<{ success: boolean; data?: unknown; error?: string }> {
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

    const text = stdout.trim()
    if (!text) return { success: true }

    try {
      return { success: true, data: JSON.parse(text) }
    } catch {
      return { success: true, data: text }
    }
  }

  private generateSteps(findings: Finding[]): RemediationStep[] {
    let order = 0
    return findings
      .filter((f) => f.type !== "clean")
      .map((finding) => {
        const action = this.mapFindingToAction(finding)
        return {
          id: crypto.randomUUID(),
          order: order++,
          action,
          target: finding.path,
          description: `${action} ${finding.type} file: ${finding.path}`,
          rollback: this.getRollbackCommand(action, finding.path),
        }
      })
  }

  private mapFindingToAction(finding: Finding): RemediationAction {
    const actionMap: Record<FindingType, RemediationAction> = {
      malware: "quarantine",
      backdoor: "quarantine",
      obfuscated: "quarantine",
      suspicious: "quarantine",
      unknown: "delete",
      clean: "skip",
    }
    return actionMap[finding.type]
  }

  private getRollbackCommand(action: RemediationAction, target: string): string {
    switch (action) {
      case "quarantine":
        return `restore ${target}`
      case "delete":
        return `restore ${target}`
      default:
        return ""
    }
  }

  private assessRisks(steps: { action: RemediationAction; target: string }[]): string[] {
    const risks: string[] = []
    const criticalActions = steps.filter(
      (s) => s.action === "delete" && (s.target.includes("wp-config") || s.target.includes(".htaccess")),
    )
    if (criticalActions.length > 0) {
      risks.push(`Critical system files will be modified: ${criticalActions.map((s) => s.target).join(", ")}`)
    }
    return risks
  }

  private async executeStep(step: { id: string; action: RemediationAction; target: string }): Promise<{
    stepId: string
    status: "success" | "failed" | "skipped"
    message?: string
    duration?: number
  }> {
    const start = Date.now()
    let cmd: string[]

    switch (step.action) {
      case "quarantine":
        cmd = ["quarantine", step.target]
        break
      case "delete":
        cmd = ["fix", "--delete", step.target]
        break
      case "restore":
        cmd = ["restore", step.target]
        break
      case "reinstall":
        return { stepId: step.id, status: "skipped", message: "Reinstall requires explicit plugin/theme specification" }
      case "clean":
        cmd = ["fix", step.target]
        break
      case "remove":
        cmd = ["fix", "--remove", step.target]
        break
      case "skip":
        return { stepId: step.id, status: "skipped" }
      default:
        return { stepId: step.id, status: "failed", message: `Unknown action: ${step.action}` }
    }

    const result = await this.run(cmd)
    return {
      stepId: step.id,
      status: result.success ? "success" : "failed",
      message: result.success ? undefined : result.error,
      duration: Date.now() - start,
    }
  }

  private parseScanResult(result: { success: boolean; data?: unknown; error?: string }, target: string): ScanResult {
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
}

interface RemediationStep {
  id: string
  order: number
  action: RemediationAction
  target: string
  description: string
  rollback?: string
}
