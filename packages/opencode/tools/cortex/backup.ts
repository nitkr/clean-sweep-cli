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

function generateBackupId(): string {
  return `backup_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`
}

function getBackupPath(target: string, backupId: string): string {
  return path.join(target, `.cortex_backups`, backupId)
}

export const CortexBackupTool = Tool.define("cortex_backup", {
  description:
    "Create a backup of the WordPress site before running cleanup operations. Backups are stored in .cortex_backups directory.",
  parameters: z.object({
    target: z.string().optional().describe("Path to WordPress installation (defaults to connected site)"),
    cliPath: z.string().optional().describe("Path to clean-sweep CLI binary (defaults to clean-sweep)"),
    backupName: z.string().optional().describe("Optional name for the backup"),
  }),
  async execute(params) {
    const target = params.target || state.target
    const cliPath = params.cliPath || state.cliPath

    if (params.target || params.cliPath) {
      configureCortexBackend(cliPath, target)
    }

    const backupId = params.backupName || generateBackupId()
    const backupPath = getBackupPath(target, backupId)

    try {
      const backend = new CleanSweepCLIAdapter(cliPath)

      const proc = spawn({
        cmd: [cliPath, "backup", target, "--output", backupPath],
        stdout: "pipe",
        stderr: "pipe",
      })

      const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
      const exitCode = await proc.exited

      if (exitCode !== 0) {
        return {
          title: `Backup Failed`,
          metadata: {
            error: true,
            reason: `exit code ${exitCode}`,
            exitCode,
            backupId: undefined as unknown as string,
            backupPath: undefined as unknown as string,
            target: undefined as unknown as string,
            success: undefined as unknown as boolean,
          },
          output: `Backup failed with exit code ${exitCode}:\n${stderr || stdout}`,
        }
      }

      let result: Record<string, unknown> = {}
      try {
        result = stdout.trim() ? JSON.parse(stdout) : {}
      } catch {
        result = { message: stdout.trim() || "Backup completed" }
      }

      const lines = [
        `<backup_complete>`,
        `<backup_id>${backupId}</backup_id>`,
        `<target>${target}</target>`,
        `<backup_path>${backupPath}</backup_path>`,
        `<timestamp>${new Date().toISOString()}</timestamp>`,
      ]

      if (result.path) {
        lines.push(`<path>${result.path}</path>`)
      }
      if (result.size) {
        lines.push(`<size>${result.size}</size>`)
      }
      if (result.files !== undefined) {
        lines.push(`<files>${result.files}</files>`)
      }

      lines.push(`</backup_complete>`)
      lines.push(``)
      lines.push(`Backup created successfully at: ${backupPath}`)
      lines.push(`Use this backup_id for restore operations: ${backupId}`)

      return {
        title: `Backup: ${backupId}`,
        metadata: {
          error: false,
          reason: "",
          exitCode: undefined as unknown as number,
          backupId,
          backupPath,
          target,
          success: true,
        },
        output: lines.join("\n"),
      }
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err)
      return {
        title: `Backup Failed`,
        metadata: {
          error: true,
          reason: error,
          exitCode: undefined as unknown as number,
          backupId: undefined as unknown as string,
          backupPath: undefined as unknown as string,
          target: undefined as unknown as string,
          success: undefined as unknown as boolean,
        },
        output: `Error creating backup: ${error}`,
      }
    }
  },
})
