export interface ReserveStatusV2 {
  readonly denom: string; readonly moduleBalance: string; readonly totalDeposited: string;
  readonly totalWithdrawn: string; readonly liability: string; readonly exactMatch: boolean;
  readonly collateralized: boolean; readonly surplus: string; readonly shortfall: string;
}
export function evaluateReserveV2(response: object, expectedDenom?: string): ReserveStatusV2;
export class ReserveUnderCollateralizedErrorV2 extends Error { readonly code: "under_collateralized"; readonly status: ReserveStatusV2; constructor(status: ReserveStatusV2); }
export function assertReserveCollateralizedV2(response: object, expectedDenom?: string): ReserveStatusV2;
