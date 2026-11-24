export function isSandboxEnabled(): boolean {
  return import.meta.env.VITE_ENABLE_SANDBOX === '1';
}
