import z from "zod"
import { Tool } from "../../src/tool/tool"
import { CleanSweepCLIAdapter } from "@cleansweep-cortex/core/adapters/clean-sweep-cli"
import type { CleanResult, RemediationPlan, ScanResult } from "@cleansweep-cortex/core/types"

const DEFAULT_CLI_PATH = "clean-sweep"
const DEFAULT_TARGET = "/home/venturer/myprojects/cleansweep-cortex/test-lab"

interface BackendState {
  cliPath: string
  target: string
  lastScanResult: ScanResult | null
  lastPlan: RemediationPlan | null
}

const state: BackendState = {
  cliPath: DEFAULT_CLI_PATH,
  target: DEFAULT_TARGET,
  lastScanResult: null,
  lastPlan: null,
}

export function configureCortexBackend(cliPath: string, target: string) {
  state.cliPath = cliPath
  state.target = target
}

function getBackend(): CleanSweepCLIAdapter {
  return new CleanSweepCLIAdapter(state.cliPath)
}

export const CortexRunCleanSweepTool = Tool.define("cortex_run_clean_sweep", {
  description:
    "Run Clean Sweep CLI to execute cleanup operations. Requires a scan to have been run first to generate a remediation plan.",
  parameters: z.object({
    target: z.string().optional().describe("Path to WordPress installation (defaults to connected site)"),
    cliPath: z.string().optional().describe("Path to clean-sweep CLI binary (defaults to clean-sweep)"),
    dryRun: z.boolean().optional().default(true).describe("Run in dry-run mode to preview changes (default: true)"),
    scanId: z.string().optional().describe("Scan ID to use for creating remediation plan"),
    planId: z.string().optional().describe("Plan ID to execute (if not provided, creates new plan from scan)"),
    confirm: z
      .boolean()
      .optional()
      .default(false)
      .describe("Confirm destructive actions (default: false, dry-run only)"),
  }),
  async execute(params) {
    const target = params.target || state.target
    const cliPath = params.cliPath || state.cliPath

    if (params.target || params.cliPath) {
      configureCortexBackend(cliPath, target)
    }

    const backend = getBackend()
    const dryRun = params.confirm ? false : (params.dryRun ?? true)

    try {
      let planId = params.planId
      let plan = state.lastPlan

      if (!plan && params.scanId && state.lastScanResult?.id === params.scanId) {
        plan = await backend.plan(state.lastScanResult)
        state.lastPlan = plan
        planId = plan.id
      }

      if (!plan && !planId) {
        return {
          title: `Clean Sweep Failed`,
          metadata: {
            error: true,
            reason: "plan_not_found",
            cleanId: "" as unknown as string,
            planId: planId || ("" as unknown as string),
            dryRun: true as unknown as boolean,
            total: 0 as unknown as number,
            succeeded: 0 as unknown as number,
            failed: 0 as unknown as number,
            skipped: 0 as unknown as number,
          },
          output: `Plan ${planId} not found. Please run a scan first.`,
        }
      }

      if (!planId) {
        return {
          title: `Clean Sweep Failed`,
          metadata: {
            error: true,
            reason: "no_plan",
            cleanId: "" as unknown as string,
            planId: "" as unknown as string,
            dryRun: true as unknown as boolean,
            total: 0 as unknown as number,
            succeeded: 0 as unknown as number,
            failed: 0 as unknown as number,
            skipped: 0 as unknown as number,
          },
          output: "No remediation plan available. Run a scan first or provide a scanId/planId.",
        }
      }

      let cleanResult: CleanResult

      if (plan) {
        cleanResult = await backend.clean(plan, dryRun)
      } else {
        return {
          title: `Clean Sweep Failed`,
          metadata: {
            error: true,
            reason: "plan_not_found",
            cleanId: "" as unknown as string,
            planId: planId || ("" as unknown as string),
            dryRun: true as unknown as boolean,
            total: 0 as unknown as number,
            succeeded: 0 as unknown as number,
            failed: 0 as unknown as number,
            skipped: 0 as unknown as number,
          },
          output: `Plan ${planId} not found. Please run a scan first.`,
        }
      }

      const lines = [
        `<clean_complete>`,
        `<clean_id>${cleanResult.id}</clean_id>`,
        `<plan_id>${cleanResult.planId}</plan_id>`,
        `<dry_run>${cleanResult.dryRun}</dry_run>`,
        `<timestamp>${new Date(cleanResult.timestamp).toISOString()}</timestamp>`,
        `<summary>`,
        `  Total: ${cleanResult.summary.total}`,
        `  Succeeded: ${cleanResult.summary.succeeded}`,
        `  Failed: ${cleanResult.summary.failed}`,
        `  Skipped: ${cleanResult.summary.skipped}`,
        `</summary>`,
        ``,
        `<executed_steps>`,
      ]

      for (const step of cleanResult.executedSteps) {
        lines.push(`<step id="${step.stepId}" status="${step.status}">`)
        lines.push(`  ${step.message || `Status: ${step.status}`}`)
        if (step.duration !== undefined) {
          lines.push(`  Duration: ${step.duration}ms`)
        }
        lines.push(`</step>`)
      }

      lines.push(`</executed_steps>`)
      lines.push(`</clean_complete>`)

      if (dryRun) {
        lines.push(``)
        lines.push(`[DRY-RUN MODE] - No actual changes were made.`)
        lines.push(`To apply changes, set dryRun: false or confirm: true`)
      }

      return {
        title: dryRun ? `Clean Sweep (Dry Run)` : `Clean Sweep Complete`,
        metadata: {
          error: false as boolean,
          reason: "",
          cleanId: cleanResult.id,
          planId: cleanResult.planId,
          dryRun: cleanResult.dryRun,
          total: cleanResult.summary.total,
          succeeded: cleanResult.summary.succeeded,
          failed: cleanResult.summary.failed,
          skipped: cleanResult.summary.skipped,
        },
        output: lines.join("\n"),
      }
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err)
      return {
        title: `Clean Sweep Failed`,
        metadata: {
          error: true,
          reason: error,
          cleanId: "" as unknown as string,
          planId: "" as unknown as string,
          dryRun: true as unknown as boolean,
          total: 0 as unknown as number,
          succeeded: 0 as unknown as number,
          failed: 0 as unknown as number,
          skipped: 0 as unknown as number,
        },
        output: `Error running clean sweep: ${error}`,
      }
    }
  },
})
