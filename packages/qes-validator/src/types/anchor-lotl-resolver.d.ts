// Ambient types for the untyped @val-protocol/anchor-lotl-resolver (.mjs, zero-dep). We reuse only
// findTslPointer (LOTL → member-state TSL pointer) + the live-fetch pattern; the CA/QC matcher is new
// here (the resolver matches TSA/QTST only).
declare module '@val-protocol/anchor-lotl-resolver' {
  export function findTslPointer(lotlXml: string, country: string): string | null;
  export function parseTokenChain(tstBase64: string): unknown;
  export function matchGrantedQtst(tslXml: string, caFingerprintHex: string, genTimeMs: number): unknown;
  export function resolveAnchorTrust(args: { tstBase64: string; tslXml: string }): { ok: boolean; spkis: string[]; evidence?: unknown; reason?: string };
  export function resolveAnchorTrustLive(args: { tstBase64: string; lotlUrl?: string; fetchImpl?: typeof fetch }): Promise<{ ok: boolean; spkis: string[]; reason?: string; tslUrl?: string }>;
}
