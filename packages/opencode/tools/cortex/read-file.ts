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

const MAX_FILE_SIZE = 5 * 1024 * 1024

export const CortexReadFileTool = Tool.define("cortex_read_file", {
  description: "Read a file from the connected WordPress site. Can analyze files for malicious content.",
  parameters: z.object({
    filePath: z.string().describe("Path to the file to read (relative to WordPress root or absolute)"),
    target: z.string().optional().describe("Path to WordPress installation (defaults to connected site)"),
    cliPath: z.string().optional().describe("Path to clean-sweep CLI binary (defaults to clean-sweep)"),
    offset: z.number().optional().describe("Line number to start reading from"),
    limit: z.number().optional().describe("Maximum number of lines to read"),
    analyze: z.boolean().optional().default(false).describe("Analyze file for malicious content"),
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
          title: `Read File Failed`,
          metadata: {
            error: true,
            reason: "is_directory",
            path: undefined as unknown as string,
            size: undefined as unknown as number,
            lines: undefined as unknown as number,
            analyzed: undefined as unknown as boolean,
            truncated: undefined as unknown as boolean,
          },
          output: `Path is a directory: ${filePath}`,
        }
      }

      if (stat.size > MAX_FILE_SIZE) {
        return {
          title: `Read File Failed`,
          metadata: {
            error: true,
            reason: "file_too_large",
            path: undefined as unknown as string,
            size: undefined as unknown as number,
            lines: undefined as unknown as number,
            analyzed: undefined as unknown as boolean,
            truncated: undefined as unknown as boolean,
          },
          output: `File too large (${stat.size} bytes). Maximum size is ${MAX_FILE_SIZE} bytes.`,
        }
      }

      const backend = new CleanSweepCLIAdapter(cliPath)

      let analysisResult: Record<string, unknown> | null = null
      if (params.analyze) {
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
            try {
              analysisResult = JSON.parse(stdout)
            } catch {
              analysisResult = { output: stdout.trim() }
            }
          } else if (stderr.trim()) {
            analysisResult = { error: stderr.trim() }
          }
        } catch {
          // Analysis failed, continue without it
        }
      }

      const content = await fs.readFile(filePath, "utf-8")
      const lines = content.split("\n")

      const offset = params.offset ?? 1
      const limit = params.limit ?? lines.length
      const start = offset - 1
      const end = Math.min(start + limit, lines.length)
      const slicedLines = lines.slice(start, end)

      const lines_output = slicedLines.map((line, i) => `${offset + i}: ${line}`).join("\n")

      const resultLines = [
        `<file_read>`,
        `<path>${filePath}</path>`,
        `<size>${stat.size}</size>`,
        `<lines>${lines.length}</lines>`,
        `<offset>${offset}</offset>`,
        `<limit>${limit}</limit>`,
        `</file_read>`,
        ``,
        `<content>`,
        lines_output,
        `</content>`,
      ]

      if (end < lines.length) {
        resultLines.push(``)
        resultLines.push(`(Showing lines ${offset}-${end} of ${lines.length}. Use offset=${end + 1} to continue.)`)
      } else {
        resultLines.push(``)
        resultLines.push(`(End of file - total ${lines.length} lines)`)
      }

      if (analysisResult) {
        resultLines.push(``)
        resultLines.push(`<analysis>`)
        resultLines.push(`  Type: ${analysisResult.type || "unknown"}`)
        resultLines.push(`  Severity: ${analysisResult.severity || "unknown"}`)
        if (analysisResult.description) {
          resultLines.push(`  Description: ${analysisResult.description}`)
        }
        if (analysisResult.malicious !== undefined) {
          resultLines.push(`  Malicious: ${analysisResult.malicious}`)
        }
        resultLines.push(`</analysis>`)
      }

      return {
        title: `Read: ${path.basename(filePath)}`,
        metadata: {
          error: false as boolean,
          reason: "",
          path: filePath,
          size: stat.size,
          lines: lines.length,
          analyzed: !!analysisResult,
          truncated: end < lines.length,
        },
        output: resultLines.join("\n"),
      }
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err)
      return {
        title: `Read File Failed`,
        metadata: {
          error: true,
          reason: error,
          path: undefined as unknown as string,
          size: undefined as unknown as number,
          lines: undefined as unknown as number,
          analyzed: undefined as unknown as boolean,
          truncated: undefined as unknown as boolean,
        },
        output: `Error reading file ${filePath}: ${error}`,
      }
    }
  },
})
