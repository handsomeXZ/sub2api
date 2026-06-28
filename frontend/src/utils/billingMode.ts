export const BILLING_MODE_TOKEN = 'token'
export const BILLING_MODE_PER_REQUEST = 'per_request'
export const BILLING_MODE_IMAGE = 'image'

export function getBillingModeLabel(mode: string | null | undefined, t: (key: string) => string): string {
  switch (mode) {
    case BILLING_MODE_PER_REQUEST: return t('admin.usage.billingModePerRequest')
    case BILLING_MODE_IMAGE: return t('admin.usage.billingModeImage')
    default: return t('admin.usage.billingModeToken')
  }
}

export function getBillingModeBadgeClass(mode: string | null | undefined): string {
  switch (mode) {
    case BILLING_MODE_PER_REQUEST: return 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300'
    case BILLING_MODE_IMAGE: return 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-300'
    default: return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
  }
}

interface ImageBillingRow {
  image_count?: number | null
  image_size?: string | null
  image_input_size?: string | null
  image_output_size?: string | null
  image_size_source?: string | null
  image_size_breakdown?: Record<string, number | null | undefined> | null
  billing_mode?: string | null
  total_cost: number
}

function hasImageBillingMetadata(row: Partial<ImageBillingRow> | null | undefined): boolean {
  if ((row?.image_count ?? 0) > 0) return true
  if (row?.image_size?.trim()) return true
  if (row?.image_input_size?.trim()) return true
  if (row?.image_output_size?.trim()) return true
  if (row?.image_size_source?.trim()) return true
  const breakdown = row?.image_size_breakdown
  return !!breakdown && Object.values(breakdown).some((count) => (count ?? 0) > 0)
}

export function isImageUsage(row: Partial<ImageBillingRow> | null | undefined): boolean {
  return getDisplayBillingMode(row) === BILLING_MODE_IMAGE
}

export function getDisplayBillingMode(row: Partial<ImageBillingRow> | null | undefined): string {
  if (row?.billing_mode) return row.billing_mode
  if (hasImageBillingMetadata(row)) return BILLING_MODE_IMAGE
  return BILLING_MODE_TOKEN
}

export function imageUnitPrice(row: Pick<ImageBillingRow, 'image_count' | 'total_cost'> | null): number {
  const imageCount = row?.image_count ?? 0
  if (imageCount <= 0) return 0
  const total = row?.total_cost ?? 0
  const price = total / imageCount
  return Number.isFinite(price) ? price : 0
}
