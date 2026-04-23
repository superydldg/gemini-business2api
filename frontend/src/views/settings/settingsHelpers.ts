import type { RefreshSettings } from '@/types/api'

export const clampInteger = (
  value: number,
  min: number,
  max: number = Number.MAX_SAFE_INTEGER,
) => Math.max(min, Math.min(max, Math.round(value)))

export const clampDecimal = (value: number, min: number, max: number) =>
  Number(Math.max(min, Math.min(max, value)).toFixed(1))

export const pickString = (fallback: string, ...values: Array<string | undefined>) => {
  for (const value of values) {
    if (typeof value === 'string') return value
  }
  return fallback
}

export const pickNumber = (fallback: number, ...values: Array<number | undefined>) => {
  for (const value of values) {
    if (Number.isFinite(value)) return Number(value)
  }
  return fallback
}

export const pickBoolean = (fallback: boolean, ...values: Array<boolean | undefined>) => {
  for (const value of values) {
    if (typeof value === 'boolean') return value
  }
  return fallback
}

export const normalizeBrowserMode = (
  mode: string | undefined,
  headless: boolean | undefined,
): RefreshSettings['browser_mode'] => {
  if (mode === 'normal' || mode === 'silent' || mode === 'headless') {
    return mode
  }
  return headless ? 'headless' : 'normal'
}

export const normalizeTempMailProvider = (
  value: string | undefined,
): RefreshSettings['temp_mail_provider'] => {
  if (
    value === 'duckmail'
    || value === 'moemail'
    || value === 'freemail'
    || value === 'gptmail'
    || value === 'cfmail'
  ) {
    return value
  }
  return 'duckmail'
}

export const toCooldownHours = (seconds: number | undefined, fallbackHours: number) => {
  if (!seconds) return fallbackHours
  return Math.max(1, Math.round(seconds / 3600))
}
