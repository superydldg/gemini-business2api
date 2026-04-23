import type { ActionMenuItem } from 'nanocat-ui'
import type { AdminAccount } from '@/types/api'
import { getAccountStateMeta } from './accountState'

export const accountBatchMenuItems: ActionMenuItem[] = [
  { key: 'enable', label: '批量启用' },
  { key: 'disable', label: '批量禁用' },
  { key: 'delete', label: '批量删除', danger: true, dividerBefore: true },
]

export const getAccountStatusLabel = (account: AdminAccount) => getAccountStateMeta(account).label

export const getAccountStatusClass = (account: AdminAccount) => getAccountStateMeta(account).badgeClass

export const shouldShowEnableAccount = (account: AdminAccount) => getAccountStateMeta(account).canEnable

export const shouldShowDisableAccount = (account: AdminAccount) => getAccountStateMeta(account).canDisable

export const getAccountRowClass = (account: AdminAccount) => getAccountStateMeta(account).rowClass

export const displayRemaining = (value: string) => {
  if (value === '已过期') return '过期'
  if (value === '未设置') return '未设置'
  return value
}

export const getRemainingClass = (account: AdminAccount) => {
  if (account.status === '已过期') return 'text-rose-600'
  if (account.status === '即将过期') return 'text-amber-700'
  if (account.status === '未设置') return 'text-muted-foreground'
  return 'text-emerald-600'
}

export const getTrialBadgeClass = (days: number | null | undefined) => {
  if (days == null) return ''
  if (days > 7) return 'bg-emerald-500 text-white'
  if (days >= 3) return 'bg-amber-500 text-white'
  return 'bg-rose-500 text-white'
}
