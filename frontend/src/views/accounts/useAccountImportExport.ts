import { computed, ref } from 'vue'
import type { useToast } from '@/composables/useToast'
import type { useAccountsStore } from '@/stores/accounts'
import { loadAccountConfigList } from './accountConfig'
import {
  buildAccountExportPayload,
  looksLikeJsonImport,
  mergeJsonImportItems,
  mergeTextImportItems,
  normalizeJsonImportList,
  parseImportLines,
} from './accountImportExport'

type AccountStore = ReturnType<typeof useAccountsStore>
type ToastApi = ReturnType<typeof useToast>
type SelectionRef = { value: Set<string> }
type SelectedCountRef = { value: number }

const exportFormatOptions = [
  { label: 'JSON', value: 'json' },
  { label: 'TXT', value: 'txt' },
] as const

const downloadText = (content: string, filename: string, mime: string) => {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

export function useAccountImportExport(
  accountsStore: AccountStore,
  toast: ToastApi,
  selectedIds: SelectionRef,
  selectedCount: SelectedCountRef,
) {
  const isImportOpen = ref(false)
  const importText = ref('')
  const importError = ref('')
  const isImporting = ref(false)
  const importFileInput = ref<HTMLInputElement | null>(null)
  const importFileName = ref('')

  const isExportOpen = ref(false)
  const exportScope = ref<'all' | 'selected'>('all')
  const exportFormat = ref<'json' | 'txt'>('json')

  const exportScopeOptions = computed(() => [
    { label: '全部账户', value: 'all' },
    { label: `当前已选 (${selectedCount.value})`, value: 'selected' },
  ])

  const openImportModal = () => {
    isImportOpen.value = true
    importText.value = ''
    importError.value = ''
    importFileName.value = ''
  }

  const closeImportModal = () => {
    isImportOpen.value = false
    importText.value = ''
    importError.value = ''
    importFileName.value = ''
  }

  const triggerImportFile = () => {
    importFileInput.value?.click()
  }

  const handleImportFile = async (event: Event) => {
    const target = event.target as HTMLInputElement | null
    const file = target?.files?.[0]
    if (!file) return

    try {
      importText.value = await file.text()
      importFileName.value = file.name
      importError.value = ''
    } catch (error: any) {
      importError.value = error.message || '文件解析失败'
    } finally {
      if (target) {
        target.value = ''
      }
    }
  }

  const applyImportedAccounts = async (
    importedIds: string[],
    successMessage: string,
    next: Awaited<ReturnType<typeof loadAccountConfigList>>,
  ) => {
    await accountsStore.updateConfig(next)
    selectedIds.value = new Set(importedIds)
    toast.success(successMessage)
  }

  const handleImportSubmit = async () => {
    importError.value = ''
    const raw = importText.value.trim()
    if (!raw) {
      importError.value = '请输入导入内容'
      return
    }

    isImporting.value = true
    try {
      const existing = await loadAccountConfigList()

      if (looksLikeJsonImport(importFileName.value, raw)) {
        const items = normalizeJsonImportList(raw)
        const { next, importedIds } = mergeJsonImportItems(existing, items)
        await applyImportedAccounts(importedIds, `导入 ${importedIds.length} 条账号配置`, next)
      } else {
        const { items, errors } = parseImportLines(raw)
        if (!items.length) {
          throw new Error(errors.length ? errors.join('，') : '未识别到有效账号')
        }
        if (errors.length) {
          throw new Error(errors.slice(0, 3).join('，'))
        }
        const { next, importedIds } = mergeTextImportItems(existing, items)
        await applyImportedAccounts(importedIds, `成功导入 ${importedIds.length} 个账户`, next)
      }

      closeImportModal()
    } catch (error: any) {
      importError.value = error.message || '导入失败'
      toast.error(error.message || '导入失败')
    } finally {
      isImporting.value = false
    }
  }

  const openExportModal = () => {
    exportScope.value = selectedCount.value > 0 ? 'selected' : 'all'
    exportFormat.value = 'json'
    isExportOpen.value = true
  }

  const closeExportModal = () => {
    isExportOpen.value = false
  }

  const exportConfig = async (format: 'json' | 'txt', scope: 'all' | 'selected') => {
    let list = await loadAccountConfigList()
    if (scope === 'selected') {
      if (!selectedIds.value.size) {
        throw new Error('当前没有选中的账户')
      }
      list = list.filter((item) => selectedIds.value.has(item.id))
    }

    const payload = buildAccountExportPayload(list, format)
    downloadText(payload.content, payload.filename, payload.mime)
    toast.success(payload.successMessage)
  }

  const runExport = async () => {
    try {
      await exportConfig(exportFormat.value, exportScope.value)
      closeExportModal()
    } catch (error: any) {
      toast.error(error.message || '导出失败')
    }
  }

  return {
    isImportOpen,
    importText,
    importError,
    isImporting,
    importFileInput,
    importFileName,
    isExportOpen,
    exportScope,
    exportFormat,
    exportScopeOptions,
    exportFormatOptions,
    openImportModal,
    closeImportModal,
    triggerImportFile,
    handleImportFile,
    handleImportSubmit,
    openExportModal,
    closeExportModal,
    runExport,
  }
}
