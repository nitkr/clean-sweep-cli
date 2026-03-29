import z from "zod"
import { Tool } from "../../src/tool/tool"
import { CleanSweepCLIAdapter } from "@cleansweep-cortex/core/adapters/clean-sweep-cli"
import { spawn } from "bun"
import path from "path"

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

export const CortexListFilesTool = Tool.define("cortex_list_files", {
  description: "List files in the connected WordPress site directory using Clean Sweep CLI.",
  parameters: z.object({
    target: z.string().optional().describe("Path to WordPress installation (defaults to connected site)"),
    cliPath: z.string().optional().describe("Path to clean-sweep CLI binary (defaults to clean-sweep)"),
    path: z.string().optional().describe("Relative path within the site to list (defaults to root)"),
    recursive: z.boolean().optional().default(false).describe("List files recursively"),
    filter: z.string().optional().describe("Filter pattern for file names"),
  }),
  async execute(params) {
    const target = params.target || state.target
    const cliPath = params.cliPath || state.cliPath

    if (params.target || params.cliPath) {
      configureCortexBackend(cliPath, target)
    }

    try {
      const args = ["list-files", target]
      if (params.path) {
        args.push("--path", params.path)
      }
      if (params.recursive) {
        args.push("--recursive")
      }
      if (params.filter) {
        args.push("--filter", params.filter)
      }

      const proc = spawn({
        cmd: [cliPath, ...args],
        stdout: "pipe",
        stderr: "pipe",
      })

      const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
      const exitCode = await proc.exited

      if (exitCode !== 0) {
        return {
          title: `List Files Failed`,
          metadata: {
            error: true,
            reason: `exit code ${exitCode}`,
            exitCode,
            target: undefined as unknown as string,
            path: undefined as unknown as string,
            count: undefined as unknown as number,
          },
          output: `Failed to list files (exit ${exitCode}):\n${stderr || stdout}`,
        }
      }

      let files: string[] = []
      try {
        const parsed = JSON.parse(stdout)
        files = Array.isArray(parsed) ? parsed : parsed.files || []
      } catch {
        files = stdout.trim().split("\n").filter(Boolean)
      }

      const lines = [
        `<files_list>`,
        `<target>${target}</target>`,
        `<path>${params.path || "/"}</path>`,
        `<count>${files.length}</count>`,
        `</files_list>`,
        ``,
      ]

      if (files.length === 0) {
        lines.push("No files found.")
      } else {
        for (const file of files) {
          lines.push(file)
        }
      }

      return {
        title: `Files: ${params.path || "/"}`,
        metadata: {
          error: false,
          reason: "",
          exitCode: undefined as unknown as number,
          target,
          path: params.path || "/",
          count: files.length,
        },
        output: lines.join("\n"),
      }
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err)
      return {
        title: `List Files Failed`,
        metadata: {
          error: true,
          reason: error,
          exitCode: undefined as unknown as number,
          target: undefined as unknown as string,
          path: undefined as unknown as string,
          count: undefined as unknown as number,
        },
        output: `Error listing files: ${error}`,
      }
    }
  },
})
