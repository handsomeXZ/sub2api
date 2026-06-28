import { describe, expect, it, vi } from 'vitest'
import { defineComponent, nextTick } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'

const { createAccountMock, checkMixedChannelRiskMock } = vi.hoisted(() => ({
  createAccountMock: vi.fn(),
  checkMixedChannelRiskMock: vi.fn()
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({
    showError: vi.fn(),
    showSuccess: vi.fn(),
    showInfo: vi.fn()
  })
}))

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({
    isSimpleMode: true
  })
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    accounts: {
      create: createAccountMock,
      checkMixedChannelRisk: checkMixedChannelRiskMock
    },
    settings: {
      getWebSearchEmulationConfig: vi.fn().mockResolvedValue({ enabled: false, providers: [] }),
      getSettings: vi.fn().mockResolvedValue({})
    },
    tlsFingerprintProfiles: {
      list: vi.fn().mockResolvedValue([])
    }
  }
}))

vi.mock('@/api/admin/accounts', () => ({
  getAntigravityDefaultModelMapping: vi.fn().mockResolvedValue([])
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

import CreateAccountModal from '../CreateAccountModal.vue'

const BaseDialogStub = defineComponent({
  name: 'BaseDialog',
  props: {
    show: {
      type: Boolean,
      default: false
    }
  },
  template: '<div v-if="show"><slot /><slot name="footer" /></div>'
})

const ModelWhitelistSelectorStub = defineComponent({
  name: 'ModelWhitelistSelector',
  props: {
    modelValue: {
      type: Array,
      default: () => []
    }
  },
  emits: ['update:modelValue'],
  template: '<div data-testid="model-whitelist-selector" />'
})

const SelectStub = defineComponent({
  name: 'SelectStub',
  props: {
    modelValue: {
      type: [String, Number, Boolean, null],
      default: ''
    },
    options: {
      type: Array,
      default: () => []
    }
  },
  emits: ['update:modelValue'],
  template: '<select v-bind="$attrs" :value="modelValue" @change="$emit(\'update:modelValue\', $event.target.value)" />'
})

function mountModal() {
  return mount(CreateAccountModal, {
    props: {
      show: true,
      proxies: [],
      groups: []
    },
    global: {
      stubs: {
        BaseDialog: BaseDialogStub,
        ConfirmDialog: BaseDialogStub,
        Select: SelectStub,
        Icon: true,
        ProxySelector: true,
        ProxyAdBanner: true,
        GroupSelector: true,
        OAuthAuthorizationFlow: true,
        ModelWhitelistSelector: ModelWhitelistSelectorStub
      }
    }
  })
}

describe('CreateAccountModal', () => {
  it('renders and submits Claude Code identity impersonation for Anthropic API key accounts', async () => {
    createAccountMock.mockReset()
    checkMixedChannelRiskMock.mockReset()
    createAccountMock.mockResolvedValue({})
    checkMixedChannelRiskMock.mockResolvedValue({ has_risk: false })

    const wrapper = mountModal()
    const apiKeyTypeButton = wrapper.findAll('button').find((button) =>
      button.text().includes('admin.accounts.claudeConsole') &&
      button.text().includes('admin.accounts.apiKey')
    )

    expect(apiKeyTypeButton).toBeTruthy()
    await apiKeyTypeButton!.trigger('click')
    await nextTick()

    const toggle = wrapper.get('[data-testid="claude-code-identity-impersonation-enabled"]')
    expect(wrapper.text()).toContain('admin.accounts.upstream.claudeCodeIdentityImpersonation')
    expect(toggle.attributes('aria-checked')).toBe('false')

    await wrapper.get('input[data-tour="account-form-name"]').setValue('Anthropic Key')
    await wrapper.get('input[type="password"]').setValue('anthropic-key-placeholder')
    await toggle.trigger('click')
    await wrapper.get('form#create-account-form').trigger('submit.prevent')
    await flushPromises()

    expect(createAccountMock).toHaveBeenCalledTimes(1)
    expect(createAccountMock.mock.calls[0]?.[0]).toMatchObject({
      platform: 'anthropic',
      type: 'apikey',
      claude_code_identity_impersonation_enabled: true
    })
  })
})
