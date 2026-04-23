import type { RefreshSettings, Settings } from '@/types/api'
import {
  normalizeBrowserMode,
  normalizeTempMailProvider,
  pickBoolean,
  pickNumber,
  pickString,
} from './settingsHelpers'

export const createDefaultRefreshSettings = (): RefreshSettings => ({
  proxy_for_auth: '',
  duckmail: {
    base_url: 'https://api.duckmail.sbs',
    api_key: '',
    verify_ssl: true,
  },
  temp_mail_provider: 'duckmail',
  moemail: {
    base_url: 'https://moemail.nanohajimi.mom',
    api_key: '',
    domain: '',
  },
  freemail: {
    base_url: 'http://your-freemail-server.com',
    jwt_token: '',
    verify_ssl: true,
    domain: '',
  },
  mail_proxy_enabled: false,
  gptmail: {
    base_url: 'https://mail.chatgpt.org.uk',
    api_key: '',
    verify_ssl: true,
    domain: '',
  },
  cfmail: {
    base_url: '',
    api_key: '',
    verify_ssl: true,
    domain: '',
  },
  browser_mode: 'normal',
  browser_headless: false,
  refresh_window_hours: 1,
  register_domain: '',
  register_default_count: 20,
  auto_refresh_accounts_seconds: 60,
  scheduled_refresh_enabled: false,
  scheduled_refresh_interval_minutes: 30,
  scheduled_refresh_cron: '',
  verification_code_resend_count: 2,
  refresh_batch_size: 5,
  refresh_batch_interval_minutes: 30,
  refresh_cooldown_hours: 12,
  delete_expired_accounts: false,
  auto_register_enabled: false,
  min_account_count: 0,
})

export const hydrateRefreshSettings = (source: Settings): RefreshSettings => {
  const defaults = createDefaultRefreshSettings()
  const current = source.refresh_settings || defaults
  const browserMode = normalizeBrowserMode(
    current.browser_mode ?? source.basic?.browser_mode,
    current.browser_headless ?? source.basic?.browser_headless,
  )

  return {
    ...defaults,
    ...current,
    proxy_for_auth: pickString(
      defaults.proxy_for_auth || '',
      current.proxy_for_auth,
      source.basic?.proxy_for_auth,
    ),
    temp_mail_provider: normalizeTempMailProvider(
      current.temp_mail_provider ?? source.basic?.temp_mail_provider,
    ),
    mail_proxy_enabled: pickBoolean(
      defaults.mail_proxy_enabled || false,
      current.mail_proxy_enabled,
      source.basic?.mail_proxy_enabled,
    ),
    browser_mode: browserMode,
    browser_headless: browserMode === 'headless',
    refresh_window_hours: pickNumber(
      defaults.refresh_window_hours || 1,
      current.refresh_window_hours,
      source.basic?.refresh_window_hours,
    ),
    register_domain: pickString(
      defaults.register_domain || '',
      current.register_domain,
      source.basic?.register_domain,
    ),
    register_default_count: pickNumber(
      defaults.register_default_count || 20,
      current.register_default_count,
      source.basic?.register_default_count,
    ),
    auto_refresh_accounts_seconds: pickNumber(
      defaults.auto_refresh_accounts_seconds || 60,
      current.auto_refresh_accounts_seconds,
      source.retry?.auto_refresh_accounts_seconds,
    ),
    scheduled_refresh_enabled: pickBoolean(
      defaults.scheduled_refresh_enabled || false,
      current.scheduled_refresh_enabled,
      source.retry?.scheduled_refresh_enabled,
    ),
    scheduled_refresh_interval_minutes: pickNumber(
      defaults.scheduled_refresh_interval_minutes || 30,
      current.scheduled_refresh_interval_minutes,
      source.retry?.scheduled_refresh_interval_minutes,
    ),
    scheduled_refresh_cron: pickString(
      defaults.scheduled_refresh_cron || '',
      current.scheduled_refresh_cron,
      source.retry?.scheduled_refresh_cron,
    ),
    verification_code_resend_count: pickNumber(
      defaults.verification_code_resend_count || 2,
      current.verification_code_resend_count,
      source.retry?.verification_code_resend_count,
    ),
    refresh_batch_size: pickNumber(
      defaults.refresh_batch_size || 5,
      current.refresh_batch_size,
      source.retry?.refresh_batch_size,
    ),
    refresh_batch_interval_minutes: pickNumber(
      defaults.refresh_batch_interval_minutes || 30,
      current.refresh_batch_interval_minutes,
      source.retry?.refresh_batch_interval_minutes,
    ),
    refresh_cooldown_hours: pickNumber(
      defaults.refresh_cooldown_hours || 12,
      current.refresh_cooldown_hours,
      source.retry?.refresh_cooldown_hours,
    ),
    delete_expired_accounts: pickBoolean(
      defaults.delete_expired_accounts || false,
      current.delete_expired_accounts,
      source.retry?.delete_expired_accounts,
    ),
    auto_register_enabled: pickBoolean(
      defaults.auto_register_enabled || false,
      current.auto_register_enabled,
      source.retry?.auto_register_enabled,
    ),
    min_account_count: pickNumber(
      defaults.min_account_count || 0,
      current.min_account_count,
      source.retry?.min_account_count,
    ),
    duckmail: {
      ...defaults.duckmail,
      ...current.duckmail,
      base_url: pickString(
        defaults.duckmail.base_url || '',
        current.duckmail?.base_url,
        source.basic?.duckmail_base_url,
      ),
      api_key: pickString(
        defaults.duckmail.api_key || '',
        current.duckmail?.api_key,
        source.basic?.duckmail_api_key,
      ),
      verify_ssl: pickBoolean(
        defaults.duckmail.verify_ssl || false,
        current.duckmail?.verify_ssl,
        source.basic?.duckmail_verify_ssl,
      ),
    },
    moemail: {
      ...defaults.moemail,
      ...current.moemail,
      base_url: pickString(
        defaults.moemail.base_url || '',
        current.moemail?.base_url,
        source.basic?.moemail_base_url,
      ),
      api_key: pickString(
        defaults.moemail.api_key || '',
        current.moemail?.api_key,
        source.basic?.moemail_api_key,
      ),
      domain: pickString(
        defaults.moemail.domain || '',
        current.moemail?.domain,
        source.basic?.moemail_domain,
      ),
    },
    freemail: {
      ...defaults.freemail,
      ...current.freemail,
      base_url: pickString(
        defaults.freemail.base_url || '',
        current.freemail?.base_url,
        source.basic?.freemail_base_url,
      ),
      jwt_token: pickString(
        defaults.freemail.jwt_token || '',
        current.freemail?.jwt_token,
        source.basic?.freemail_jwt_token,
      ),
      verify_ssl: pickBoolean(
        defaults.freemail.verify_ssl || false,
        current.freemail?.verify_ssl,
        source.basic?.freemail_verify_ssl,
      ),
      domain: pickString(
        defaults.freemail.domain || '',
        current.freemail?.domain,
        source.basic?.freemail_domain,
      ),
    },
    gptmail: {
      ...defaults.gptmail,
      ...current.gptmail,
      base_url: pickString(
        defaults.gptmail.base_url || '',
        current.gptmail?.base_url,
        source.basic?.gptmail_base_url,
      ),
      api_key: pickString(
        defaults.gptmail.api_key || '',
        current.gptmail?.api_key,
        source.basic?.gptmail_api_key,
      ),
      verify_ssl: pickBoolean(
        defaults.gptmail.verify_ssl || false,
        current.gptmail?.verify_ssl,
        source.basic?.gptmail_verify_ssl,
      ),
      domain: pickString(
        defaults.gptmail.domain || '',
        current.gptmail?.domain,
        source.basic?.gptmail_domain,
      ),
    },
    cfmail: {
      ...defaults.cfmail,
      ...current.cfmail,
      base_url: pickString(
        defaults.cfmail.base_url || '',
        current.cfmail?.base_url,
        source.basic?.cfmail_base_url,
      ),
      api_key: pickString(
        defaults.cfmail.api_key || '',
        current.cfmail?.api_key,
        source.basic?.cfmail_api_key,
      ),
      verify_ssl: pickBoolean(
        defaults.cfmail.verify_ssl || false,
        current.cfmail?.verify_ssl,
        source.basic?.cfmail_verify_ssl,
      ),
      domain: pickString(
        defaults.cfmail.domain || '',
        current.cfmail?.domain,
        source.basic?.cfmail_domain,
      ),
    },
  }
}

export const syncRefreshMirrors = (payload: Settings) => {
  const refreshSettings = hydrateRefreshSettings(payload)
  const browserMode = normalizeBrowserMode(
    refreshSettings.browser_mode,
    refreshSettings.browser_headless,
  )

  refreshSettings.browser_mode = browserMode
  refreshSettings.browser_headless = browserMode === 'headless'
  payload.refresh_settings = refreshSettings

  payload.basic.proxy_for_auth = refreshSettings.proxy_for_auth
  payload.basic.duckmail_base_url = refreshSettings.duckmail.base_url
  payload.basic.duckmail_api_key = refreshSettings.duckmail.api_key
  payload.basic.duckmail_verify_ssl = refreshSettings.duckmail.verify_ssl
  payload.basic.temp_mail_provider = refreshSettings.temp_mail_provider
  payload.basic.moemail_base_url = refreshSettings.moemail.base_url
  payload.basic.moemail_api_key = refreshSettings.moemail.api_key
  payload.basic.moemail_domain = refreshSettings.moemail.domain
  payload.basic.freemail_base_url = refreshSettings.freemail.base_url
  payload.basic.freemail_jwt_token = refreshSettings.freemail.jwt_token
  payload.basic.freemail_verify_ssl = refreshSettings.freemail.verify_ssl
  payload.basic.freemail_domain = refreshSettings.freemail.domain
  payload.basic.mail_proxy_enabled = refreshSettings.mail_proxy_enabled
  payload.basic.gptmail_base_url = refreshSettings.gptmail.base_url
  payload.basic.gptmail_api_key = refreshSettings.gptmail.api_key
  payload.basic.gptmail_verify_ssl = refreshSettings.gptmail.verify_ssl
  payload.basic.gptmail_domain = refreshSettings.gptmail.domain
  payload.basic.cfmail_base_url = refreshSettings.cfmail.base_url
  payload.basic.cfmail_api_key = refreshSettings.cfmail.api_key
  payload.basic.cfmail_verify_ssl = refreshSettings.cfmail.verify_ssl
  payload.basic.cfmail_domain = refreshSettings.cfmail.domain
  payload.basic.browser_mode = refreshSettings.browser_mode
  payload.basic.browser_headless = refreshSettings.browser_headless
  payload.basic.refresh_window_hours = refreshSettings.refresh_window_hours
  payload.basic.register_domain = refreshSettings.register_domain
  payload.basic.register_default_count = refreshSettings.register_default_count

  payload.retry.auto_refresh_accounts_seconds = refreshSettings.auto_refresh_accounts_seconds
  payload.retry.scheduled_refresh_enabled = refreshSettings.scheduled_refresh_enabled
  payload.retry.scheduled_refresh_interval_minutes = refreshSettings.scheduled_refresh_interval_minutes
  payload.retry.scheduled_refresh_cron = refreshSettings.scheduled_refresh_cron
  payload.retry.verification_code_resend_count = refreshSettings.verification_code_resend_count
  payload.retry.refresh_batch_size = refreshSettings.refresh_batch_size
  payload.retry.refresh_batch_interval_minutes = refreshSettings.refresh_batch_interval_minutes
  payload.retry.refresh_cooldown_hours = refreshSettings.refresh_cooldown_hours
  payload.retry.delete_expired_accounts = refreshSettings.delete_expired_accounts
  payload.retry.auto_register_enabled = refreshSettings.auto_register_enabled
  payload.retry.min_account_count = refreshSettings.min_account_count
}
