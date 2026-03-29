import z from "zod"
import { Tool } from "../../src/tool/tool"
import { CleanSweepCLIAdapter } from "@cleansweep-cortex/core/adapters/clean-sweep-cli"
import type { ScanResult } from "@cleansweep-cortex/core/types"

const DEFAULT_CLI_PATH = "clean-sweep"
const DEFAULT_TARGET = "/home/venturer/myprojects/cleansweep-cortex/test-lab"

interface BackendState {
  cliPath: string
  target: string
  backend: CleanSweepCLIAdapter | null
}

const state: BackendState = {
  cliPath: DEFAULT_CLI_PATH,
  target: DEFAULT_TARGET,
  backend: null,
}

export function configureCortexBackend(cliPath: string, target: string) {
  state.cliPath = cliPath
  state.target = target
  state.backend = new CleanSweepCLIAdapter(cliPath)
}

function getBackend(): CleanSweepCLIAdapter {
  if (!state.backend) {
    state.backend = new CleanSweepCLIAdapter(state.cliPath)
  }
  return state.backend
}

export const CortexScanTool = Tool.define("cortex_scan", {
  description:
    "Scan a WordPress site for malware using Clean Sweep CLI. Returns detailed findings with severity levels.",
  parameters: z.object({
    target: z.string().optional().describe("Path to WordPress installation to scan (defaults to connected site)"),
    cliPath: z.string().optional().describe("Path to clean-sweep CLI binary (defaults to clean-sweep)"),
  }),
  async execute(params) {
    const target = params.target || state.target
    const cliPath = params.cliPath || state.cliPath

    if (params.cliPath || params.target) {
      configureCortexBackend(cliPath, target)
    }

    const backend = getBackend()

    try {
      const result: ScanResult = await backend.scan(target)

      const lines = [
        `<scan_complete>`,
        `<target>${result.target}</target>`,
        `<scan_id>${result.id}</scan_id>`,
        `<timestamp>${new Date(result.timestamp).toISOString()}</timestamp>`,
        `<summary>`,
        `  Total: ${result.summary.total}`,
        `  Critical: ${result.summary.critical}`,
        `  High: ${result.summary.high}`,
        `  Medium: ${result.summary.medium}`,
        `  Low: ${result.summary.low}`,
        `  Clean: ${result.summary.clean}`,
        `</summary>`,
        ``,
        `<findings>`,
      ]

      for (const finding of result.findings) {
        lines.push(`<finding>`)
        lines.push(`  ID: ${finding.id}`)
        lines.push(`  Type: ${finding.type}`)
        lines.push(`  Severity: ${finding.severity}`)
        lines.push(`  Confidence: ${(finding.confidence * 100).toFixed(1)}%`)
        lines.push(`  Path: ${finding.path}`)
        lines.push(`  Description: ${finding.description}`)
        if (finding.evidence && finding.evidence.length > 0) {
          lines.push(`  Evidence:`)
          for (const e of finding.evidence.slice(0, 5)) {
            lines.push(`    - ${e}`)
          }
        }
        lines.push(`</finding>`)
      }

      lines.push(`</findings>`)
      lines.push(`</scan_complete>`)

      return {
        title: `Scan: ${result.target}`,
        metadata: {
          error: false as boolean,
          reason: "",
          total: result.summary.total,
          critical: result.summary.critical,
          high: result.summary.high,
          medium: result.summary.medium,
          low: result.summary.low,
          clean: result.summary.clean,
          scanId: result.id,
        },
        output: lines.join("\n"),
      }
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err)
      return {
        title: `Scan Failed`,
        metadata: {
          error: true,
          reason: error,
          total: undefined as unknown as number,
          critical: undefined as unknown as number,
          high: undefined as unknown as number,
          medium: undefined as unknown as number,
          low: undefined as unknown as number,
          clean: undefined as unknown as number,
          scanId: undefined as unknown as string,
        },
        output: `Error scanning ${target}: ${error}`,
      }
    }
  },
})
