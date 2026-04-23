import { computed, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import type { useAccountsStore } from '@/stores/accounts'
import {
  accountStatusOptions,
  resolveAccountStateCode,
  type AccountStatusFilter,
} from './accountState'

type AccountStore = ReturnType<typeof useAccountsStore>

const ACCOUNTS_VIEW_MODE_STORAGE_KEY = 'accounts_view_mode'

const loadViewMode = (): 'table' | 'card' => {
  if (typeof window === 'undefined') return 'table'
  return window.localStorage.getItem(ACCOUNTS_VIEW_MODE_STORAGE_KEY) === 'card'
    ? 'card'
    : 'table'
}

const persistViewMode = (value: 'table' | 'card') => {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(ACCOUNTS_VIEW_MODE_STORAGE_KEY, value)
}

export function useAccountsPage(accountsStore: AccountStore) {
  const { accounts } = storeToRefs(accountsStore)

  const searchQuery = ref('')
  const statusFilter = ref<AccountStatusFilter>('all')
  const selectedIds = ref<Set<string>>(new Set())
  const viewMode = ref<'table' | 'card'>(loadViewMode())
  const currentPage = ref(1)
  const pageSize = ref(50)

  const pageSizeOptions = [
    { label: '20 / 页', value: 20 },
    { label: '50 / 页', value: 50 },
    { label: '100 / 页', value: 100 },
  ]

  const selectedCount = computed(() => selectedIds.value.size)
  const filteredAccounts = computed(() => {
    const query = searchQuery.value.trim().toLowerCase()
    return accounts.value.filter((account) => {
      const matchesQuery = !query || account.id.toLowerCase().includes(query)
      const matchesStatus =
        statusFilter.value === 'all' || resolveAccountStateCode(account) === statusFilter.value
      return matchesQuery && matchesStatus
    })
  })

  const totalPages = computed(() =>
    Math.max(1, Math.ceil(filteredAccounts.value.length / pageSize.value)),
  )
  const paginatedAccounts = computed(() => {
    const start = (currentPage.value - 1) * pageSize.value
    return filteredAccounts.value.slice(start, start + pageSize.value)
  })
  const allSelected = computed(() =>
    filteredAccounts.value.length > 0 &&
    filteredAccounts.value.every((account) => selectedIds.value.has(account.id)),
  )

  watch(viewMode, (value) => {
    persistViewMode(value)
  })

  watch([searchQuery, statusFilter, pageSize], () => {
    currentPage.value = 1
  })

  watch(filteredAccounts, () => {
    if (currentPage.value > totalPages.value) {
      currentPage.value = totalPages.value
    }
  })

  watch(accounts, (value) => {
    const validIds = new Set(value.map((account) => account.id))
    selectedIds.value = new Set(
      Array.from(selectedIds.value).filter((accountId) => validIds.has(accountId)),
    )
  })

  const toggleSelect = (accountId: string, checked?: boolean) => {
    const next = new Set(selectedIds.value)
    const shouldSelect = typeof checked === 'boolean' ? checked : !next.has(accountId)
    if (shouldSelect) {
      next.add(accountId)
    } else {
      next.delete(accountId)
    }
    selectedIds.value = next
  }

  const toggleSelectAll = () => {
    if (allSelected.value) {
      selectedIds.value = new Set()
      return
    }
    selectedIds.value = new Set(filteredAccounts.value.map((account) => account.id))
  }

  const clearSelection = () => {
    selectedIds.value = new Set()
  }

  const refreshAccounts = async () => {
    await accountsStore.loadAccounts()
    clearSelection()
  }

  return {
    searchQuery,
    statusFilter,
    statusOptions: accountStatusOptions,
    selectedIds,
    viewMode,
    currentPage,
    pageSize,
    pageSizeOptions,
    selectedCount,
    filteredAccounts,
    paginatedAccounts,
    totalPages,
    allSelected,
    refreshAccounts,
    toggleSelect,
    toggleSelectAll,
    clearSelection,
  }
}
