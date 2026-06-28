import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const apiMocks = vi.hoisted(() => ({
  getUserApiKeys: vi.fn(),
  getAllGroups: vi.fn(),
  updateApiKeyGroup: vi.fn()
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    users: {
      getUserApiKeys: apiMocks.getUserApiKeys
    },
    groups: {
      getAll: apiMocks.getAllGroups
    },
    apiKeys: {
      updateApiKeyGroup: apiMocks.updateApiKeyGroup
    }
  }
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({
    showError: vi.fn(),
    showSuccess: vi.fn()
  })
}))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string) => key
    })
  }
})

vi.mock('@/components/common/BaseDialog.vue', () => ({
  default: {
    name: 'BaseDialog',
    props: ['show', 'title', 'width'],
    template: '<div v-if="show"><slot /></div>'
  }
}))

import UserApiKeysModal from '../UserApiKeysModal.vue'

async function mountAndOpen() {
  const wrapper = mount(UserApiKeysModal, {
    props: {
      show: false,
      user: {
        id: 7,
        email: 'user@example.com',
        username: 'demo-user'
      }
    },
    global: {
      stubs: {
        GroupBadge: true,
        GroupOptionItem: true,
        Teleport: true
      }
    }
  })

  await wrapper.setProps({ show: true })
  await flushPromises()

  return wrapper
}

describe('UserApiKeysModal', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apiMocks.getAllGroups.mockResolvedValue([])
    apiMocks.updateApiKeyGroup.mockResolvedValue({})
    apiMocks.getUserApiKeys.mockResolvedValue({
      items: [
        {
          id: 101,
          name: 'Primary User Key',
          key: 'user-key-redacted-placeholder',
          status: 'active',
          group_id: null,
          group: null,
          created_at: '2026-06-27T00:00:00Z',
          claude_code_identity_impersonation_enabled: true,
          extra: {
            claude_code_identity_impersonation_enabled: true
          }
        }
      ]
    })
  })

  it('does not render Claude Code identity impersonation controls for user API keys', async () => {
    const wrapper = await mountAndOpen()

    expect(apiMocks.getUserApiKeys).toHaveBeenCalledWith(7)
    expect(wrapper.text()).toContain('Primary User Key')
    expect(wrapper.find('[role="switch"]').exists()).toBe(false)
    expect(wrapper.html()).not.toContain('claude_code_identity_impersonation_enabled')
    expect(wrapper.html()).not.toContain('claudeCodeIdentityImpersonation')
  })
})
