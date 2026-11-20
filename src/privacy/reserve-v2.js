import { canonicalAssetDenomV1 } from "./asset-denom.js";
const maxUint256=(1n<<256n)-1n;
function decimal(value,label,bounded=true) {
  if(typeof value!=="string"||!/^(0|[1-9][0-9]*)$/.test(value))throw new Error(`invalid reserve ${label}`);
  const parsed=BigInt(value);
  if(bounded&&parsed>maxUint256)throw new Error(`reserve ${label} exceeds uint256`);
  return parsed;
}
function alias(source,snake,camel,normalize) {
  const a=source[snake],b=source[camel],value=normalize(a===undefined?b:a,snake);
  if(a!==undefined&&b!==undefined&&value!==normalize(b,camel))throw new Error(`reserve ${snake} aliases disagree`);
  return value;
}
const boolean=(value,label)=>{if(typeof value!=="boolean")throw new Error(`invalid reserve ${label}`);return value;};
/** Core v0.6.1 EvaluateReserve semantics. A surplus is valid collateralization;
 * an actual shortfall is a distinct result, not missing audit evidence. */
export function evaluateReserveV2(response,expectedDenom) {
  if(!response||typeof response!=="object"||Array.isArray(response))throw new Error("reserve response required");
  const denom=canonicalAssetDenomV1(response.denom);
  if(expectedDenom!==undefined&&denom!==expectedDenom)throw new Error("reserve denom mismatch");
  const balance=alias(response,"module_balance","moduleBalance",decimal);
  const deposited=alias(response,"total_deposited","totalDeposited",(v,l)=>decimal(v,l,false));
  const withdrawn=alias(response,"total_withdrawn","totalWithdrawn",(v,l)=>decimal(v,l,false));
  const expected=alias(response,"expected_module_balance","expectedModuleBalance",decimal);
  const liability=decimal(response.liability,"liability");
  const surplus=decimal(response.surplus,"surplus"),shortfall=decimal(response.shortfall,"shortfall");
  const exact=alias(response,"invariant_holds","invariantHolds",boolean);
  const collateralized=boolean(response.collateralized,"collateralized");
  if(deposited<withdrawn||deposited-withdrawn!==liability||expected!==liability)throw new Error("reserve liability arithmetic mismatch");
  const difference=balance-liability;
  if(exact!==(difference===0n)||collateralized!==(difference>=0n)||surplus!==(difference>0n?difference:0n)||shortfall!==(difference<0n?-difference:0n))throw new Error("reserve status arithmetic mismatch");
  return Object.freeze({denom,moduleBalance:balance.toString(),totalDeposited:deposited.toString(),totalWithdrawn:withdrawn.toString(),liability:liability.toString(),exactMatch:exact,collateralized,surplus:surplus.toString(),shortfall:shortfall.toString()});
}
export class ReserveUnderCollateralizedErrorV2 extends Error {
  constructor(status){super("privacy reserve is under-collateralized");this.name="ReserveUnderCollateralizedErrorV2";this.code="under_collateralized";this.status=status;}
}
export function assertReserveCollateralizedV2(response,expectedDenom) {
  const status=evaluateReserveV2(response,expectedDenom);
  if(!status.collateralized)throw new ReserveUnderCollateralizedErrorV2(status);
  return status;
}
