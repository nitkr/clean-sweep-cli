export { CortexScanTool } from "./scan"
export { CortexBackupTool } from "./backup"
export { CortexRunCleanSweepTool } from "./run-clean-sweep"
export { CortexListFilesTool } from "./list-files"
export { CortexReadFileTool } from "./read-file"
export { CortexAnalyzeFileTool } from "./analyze-file"
export { configureCortexBackend } from "./scan"

import { CortexScanTool } from "./scan"
import { CortexBackupTool } from "./backup"
import { CortexRunCleanSweepTool } from "./run-clean-sweep"
import { CortexListFilesTool } from "./list-files"
import { CortexReadFileTool } from "./read-file"
import { CortexAnalyzeFileTool } from "./analyze-file"
import type { Tool } from "../../src/tool/tool"

export const cortexTools: Tool.Info[] = [
  CortexScanTool,
  CortexBackupTool,
  CortexRunCleanSweepTool,
  CortexListFilesTool,
  CortexReadFileTool,
  CortexAnalyzeFileTool,
]
