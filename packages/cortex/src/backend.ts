import type { ScanResult, RemediationPlan, CleanResult, VerifyResult, BackendConfig, BackendCapability } from "./types"

export abstract class RemediationBackend {
  abstract readonly config: BackendConfig

  abstract scan(target: string): Promise<ScanResult>
  abstract plan(scanResults: ScanResult): Promise<RemediationPlan>
  abstract clean(plan: RemediationPlan, dryRun?: boolean): Promise<CleanResult>
  abstract verify(cleanResults: CleanResult): Promise<VerifyResult>

  hasCapability(capability: BackendCapability): boolean {
    return this.config.capabilities.includes(capability)
  }
}
