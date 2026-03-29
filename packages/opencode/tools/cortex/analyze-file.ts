import z from "zod"
import { Tool } from "../../src/tool/tool"
import { CleanSweepCLIAdapter } from "@cleansweep-cortex/core/adapters/clean-sweep-cli"
import { spawn } from "bun"
import * as fs from "fs/promises"
import * as path from "path"

const DEFAULT_CLI_PATH = "clean-sweep"
const DEFAULT_TARGET = "/home/venturer/myprojects/cleansweep-cortex/test-lab"

interface BackendState {
  cliPath: string
  target: string
}

const state: BackendState = {
  cliPath: DEFAULT_CLI_PATH,
  target: DEFAULT_TARGET,
}

export function configureCortexBackend(cliPath: string, target: string) {
  state.cliPath = cliPath
  state.target = target
}

const MALICIOUS_PATTERNS = [
  {
    pattern: /eval\s*\(\s*base64_decode/i,
    type: "obfuscated",
    severity: "high",
    description: "Base64 decode followed by eval",
  },
  {
    pattern: /system\s*\(\s*\$_(GET|POST|REQUEST)/i,
    type: "backdoor",
    severity: "critical",
    description: "System command execution via user input",
  },
  {
    pattern: /shell_exec|passthru|popen|proc_open/i,
    type: "suspicious",
    severity: "high",
    description: "Command execution function",
  },
  {
    pattern: /assert\s*\(\s*\$_(GET|POST|REQUEST)/i,
    type: "backdoor",
    severity: "critical",
    description: "Assert code execution via user input",
  },
  {
    pattern: /\$_(GET|POST|REQUEST)\s*\[.*\]\s*\(\s*\)/i,
    type: "backdoor",
    severity: "critical",
    description: "Dynamic function call with user input",
  },
  {
    pattern: /preg_replace\s*\(\s*["'].*e["']\s*,/i,
    type: "backdoor",
    severity: "critical",
    description: "Preg_replace with eval modifier",
  },
  {
    pattern: /create_function\s*\(/i,
    type: "suspicious",
    severity: "medium",
    description: "Dynamic function creation",
  },
  {
    pattern: /call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST)/i,
    type: "backdoor",
    severity: "critical",
    description: "Callback function with user input",
  },
  {
    pattern: /base64_decode\s*\(\s*\$_(GET|POST|REQUEST)/i,
    type: "obfuscated",
    severity: "high",
    description: "Base64 decode with user input",
  },
  {
    pattern: /<?php\s*\$[a-zA-Z_]+\s*=\s*["'][^"']+["']\s*;\s*@?eval/i,
    type: "malware",
    severity: "critical",
    description: "Encoded payload assignment",
  },
  {
    pattern: /goto\s+\w+.*eval|eval\s*\(.*\$/i,
    type: "obfuscated",
    severity: "high",
    description: "Obfuscated control flow with eval",
  },
]

export const CortexAnalyzeFileTool = Tool.define("cortex_analyze_file", {
  description:
    "Analyze a file from the WordPress site for malicious content. Checks for common malware patterns, obfuscated code, and backdoors.",
  parameters: z.object({
    filePath: z.string().describe("Path to the file to analyze (relative to WordPress root or absolute)"),
    target: z.string().optional().describe("Path to WordPress installation (defaults to connected site)"),
    cliPath: z.string().optional().describe("Path to clean-sweep CLI binary (defaults to clean-sweep)"),
    deepScan: z.boolean().optional().default(false).describe("Enable deep analysis including entropy detection"),
  }),
  async execute(params) {
    let target = params.target || state.target
    const cliPath = params.cliPath || state.cliPath

    if (params.target || params.cliPath) {
      configureCortexBackend(cliPath, target)
    }

    const filePath = params.filePath.startsWith("/") ? params.filePath : path.join(target, params.filePath)

    try {
      const stat = await fs.stat(filePath)

      if (stat.isDirectory()) {
        return {
          title: `Analyze File Failed`,
          metadata: {
            error: true,
            reason: "is_directory",
            path: undefined as unknown as string,
            size: undefined as unknown as number,
            findingsCount: undefined as unknown as number,
            severity: undefined as unknown as string,
            type: undefined as unknown as string,
            malicious: undefined as unknown as boolean,
          },
          output: `Path is a directory: ${filePath}`,
        }
      }

      const content = await fs.readFile(filePath, "utf-8")
      const findings: Array<{
        pattern: string
        type: string
        severity: string
        description: string
        line?: number
        match?: string
      }> = []

      const contentLines = content.split("\n")
      for (let i = 0; i < contentLines.length; i++) {
        const line = contentLines[i]
        for (const mp of MALICIOUS_PATTERNS) {
          if (mp.pattern.test(line)) {
            findings.push({
              pattern: mp.pattern.source,
              type: mp.type,
              severity: mp.severity,
              description: mp.description,
              line: i + 1,
              match: line.substring(0, 100) + (line.length > 100 ? "..." : ""),
            })
          }
        }
      }

      const cliAnalysis = await (async () => {
        try {
          const proc = spawn({
            cmd: [cliPath, "analyze", filePath],
            stdout: "pipe",
            stderr: "pipe",
          })
          const [stdout, stderr] = await Promise.all([
            new Response(proc.stdout).text(),
            new Response(proc.stderr).text(),
          ])
          const exitCode = await proc.exited
          if (exitCode === 0 && stdout.trim()) {
            return JSON.parse(stdout)
          }
          return { error: stderr.trim() || "Analysis failed" }
        } catch {
          return null
        }
      })()

      const overallSeverity =
        findings.length > 0
          ? findings.some((f) => f.severity === "critical")
            ? "critical"
            : findings.some((f) => f.severity === "high")
              ? "high"
              : findings.some((f) => f.severity === "medium")
                ? "medium"
                : "low"
          : cliAnalysis?.severity || "clean"

      const overallType = findings.length > 0 ? findings[0].type : cliAnalysis?.type || "clean"

      const lines = [
        `<file_analysis>`,
        `<path>${filePath}</path>`,
        `<size>${stat.size}</size>`,
        `<findings_count>${findings.length}</findings_count>`,
        `<overall_severity>${overallSeverity}</overall_severity>`,
        `<overall_type>${overallType}</overall_type>`,
        `</file_analysis>`,
        ``,
      ]

      if (findings.length > 0) {
        lines.push(`<threats>`)
        for (const f of findings) {
          lines.push(`<threat type="${f.type}" severity="${f.severity}" line="${f.line}">`)
          lines.push(`  Description: ${f.description}`)
          lines.push(`  Match: ${f.match}`)
          lines.push(`</threat>`)
        }
        lines.push(`</threats>`)
      } else {
        lines.push(`<status>No malicious patterns detected</status>`)
      }

      if (cliAnalysis && !cliAnalysis.error) {
        lines.push(``)
        lines.push(`<cli_analysis>`)
        lines.push(`  Type: ${cliAnalysis.type || "unknown"}`)
        lines.push(`  Severity: ${cliAnalysis.severity || "unknown"}`)
        if (cliAnalysis.description) {
          lines.push(`  Description: ${cliAnalysis.description}`)
        }
        if (cliAnalysis.signature) {
          lines.push(`  Signature: ${cliAnalysis.signature}`)
        }
        lines.push(`</cli_analysis>`)
      } else if (cliAnalysis?.error) {
        lines.push(``)
        lines.push(`CLI analysis note: ${cliAnalysis.error}`)
      }

      lines.push(``)
      lines.push(`Analysis complete. ${findings.length} threat(s) found.`)

      return {
        title: `Analyze: ${path.basename(filePath)}`,
        metadata: {
          error: false as boolean,
          reason: "",
          path: filePath,
          size: stat.size,
          findingsCount: findings.length,
          severity: overallSeverity,
          type: overallType,
          malicious: overallSeverity !== "clean" && overallSeverity !== "info",
        },
        output: lines.join("\n"),
      }
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err)
      return {
        title: `Analyze File Failed`,
        metadata: {
          error: true,
          reason: error,
          path: undefined as unknown as string,
          size: undefined as unknown as number,
          findingsCount: undefined as unknown as number,
          severity: undefined as unknown as string,
          type: undefined as unknown as string,
          malicious: undefined as unknown as boolean,
        },
        output: `Error analyzing file ${filePath}: ${error}`,
      }
    }
  },
})
