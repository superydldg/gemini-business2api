import type { Settings } from '@/types/api'
import { pickNumber, pickString } from './settingsHelpers'
import { hydrateRefreshSettings } from './settingsRefresh'

export const normalizeSettings = (value: Settings): Settings => {
  const next = JSON.parse(JSON.stringify(value)) as Settings

  next.basic = next.basic || {}
  next.basic.api_key = pickString('', next.basic.api_key)
  next.basic.base_url = pickString('', next.basic.base_url)
  next.basic.proxy_for_chat = pickString('', next.basic.proxy_for_chat)
  next.basic.image_expire_hours = pickNumber(12, next.basic.image_expire_hours)

  next.retry = next.retry || {
    max_account_switch_tries: 5,
    text_rate_limit_cooldown_seconds: 7200,
    images_rate_limit_cooldown_seconds: 14400,
    videos_rate_limit_cooldown_seconds: 14400,
    session_cache_ttl_seconds: 3600,
  }
  next.retry.max_account_switch_tries = pickNumber(5, next.retry.max_account_switch_tries)
  next.retry.rate_limit_cooldown_seconds = pickNumber(
    next.retry.text_rate_limit_cooldown_seconds,
    next.retry.rate_limit_cooldown_seconds,
  )
  next.retry.text_rate_limit_cooldown_seconds = pickNumber(
    7200,
    next.retry.text_rate_limit_cooldown_seconds,
  )
  next.retry.images_rate_limit_cooldown_seconds = pickNumber(
    14400,
    next.retry.images_rate_limit_cooldown_seconds,
  )
  next.retry.videos_rate_limit_cooldown_seconds = pickNumber(
    14400,
    next.retry.videos_rate_limit_cooldown_seconds,
  )
  next.retry.session_cache_ttl_seconds = pickNumber(
    3600,
    next.retry.session_cache_ttl_seconds,
  )

  next.image_generation = next.image_generation || {
    enabled: false,
    supported_models: [],
    output_format: 'base64',
  }
  next.image_generation.enabled = next.image_generation.enabled ?? false
  next.image_generation.supported_models = Array.isArray(next.image_generation.supported_models)
    ? next.image_generation.supported_models
    : []
  next.image_generation.output_format =
    next.image_generation.output_format === 'url' ? 'url' : 'base64'

  next.video_generation = next.video_generation || { output_format: 'html' }
  next.video_generation.output_format = next.video_generation.output_format === 'url'
    ? 'url'
    : next.video_generation.output_format === 'markdown'
      ? 'markdown'
      : 'html'

  next.quota_limits = next.quota_limits || {
    enabled: true,
    text_daily_limit: 120,
    images_daily_limit: 2,
    videos_daily_limit: 1,
  }
  next.quota_limits.enabled = next.quota_limits.enabled ?? true
  next.quota_limits.text_daily_limit = pickNumber(120, next.quota_limits.text_daily_limit)
  next.quota_limits.images_daily_limit = pickNumber(2, next.quota_limits.images_daily_limit)
  next.quota_limits.videos_daily_limit = pickNumber(1, next.quota_limits.videos_daily_limit)

  next.public_display = next.public_display || {}
  next.public_display.logo_url = pickString('', next.public_display.logo_url)
  next.public_display.chat_url = pickString('', next.public_display.chat_url)

  next.session = next.session || { expire_hours: 24 }
  next.session.expire_hours = pickNumber(24, next.session.expire_hours)

  next.refresh_settings = hydrateRefreshSettings(next)

  return next
}
