export interface ScanResult {
  id: string
  target: string
  timestamp: number
  findings: Finding[]
  summary: ScanSummary
}

export interface Finding {
  id: string
  type: FindingType
  path: string
  severity: Severity
  confidence: number
  description: string
  evidence?: string[]
  metadata?: Record<string, unknown>
}

export type FindingType = "malware" | "suspicious" | "backdoor" | "obfuscated" | "unknown" | "clean"

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export interface ScanSummary {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  clean: number
}

export interface RemediationPlan {
  id: string
  scanId: string
  steps: RemediationStep[]
  estimatedDuration: number
  risks: string[]
}

export interface RemediationStep {
  id: string
  order: number
  action: RemediationAction
  target: string
  description: string
  rollback?: string
}

export type RemediationAction = "delete" | "quarantine" | "restore" | "reinstall" | "clean" | "remove" | "skip"

export interface CleanResult {
  id: string
  planId: string
  dryRun: boolean
  timestamp: number
  executedSteps: ExecutedStep[]
  summary: CleanSummary
}

export interface ExecutedStep {
  stepId: string
  status: ExecutionStatus
  message?: string
  duration?: number
}

export type ExecutionStatus = "success" | "failed" | "skipped" | "pending"

export interface CleanSummary {
  total: number
  succeeded: number
  failed: number
  skipped: number
}

export interface VerifyResult {
  id: string
  cleanId: string
  timestamp: number
  verified: boolean
  checks: VerificationCheck[]
  report: VerificationReport
}

export interface VerificationCheck {
  name: string
  passed: boolean
  details?: string
}

export interface VerificationReport {
  filesScanned: number
  threatsRemoved: number
  integrityRestored: boolean
  hardeningApplied: boolean
}

export interface BackendConfig {
  name: string
  version: string
  capabilities: BackendCapability[]
}

export type BackendCapability = "scan" | "plan" | "clean" | "verify" | "dry_run" | "rollback"
