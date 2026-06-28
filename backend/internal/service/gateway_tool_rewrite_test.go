package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type toolNameRewriteTestContext struct {
	values map[string]any
}

func newToolNameRewriteTestContext(rw *ToolNameRewrite) toolNameRewriteTestContext {
	return toolNameRewriteTestContext{values: map[string]any{toolNameRewriteKey: rw}}
}

func (ctx toolNameRewriteTestContext) Get(key string) (any, bool) {
	value, ok := ctx.values[key]
	return value, ok
}

func TestRestoreToolNamesInBytes_LongestFirst(t *testing.T) {
	// 当假名 "abc_12" 是另一个更长假名的子串（真实场景极少但算法必须防御）时，
	// 长的必须先替换。本测试用显式构造的映射来验证排序不变量。
	rw := &ToolNameRewrite{
		Forward: map[string]string{"foo": "abc_12", "bar": "abc_12_ext"},
		Reverse: map[string]string{"abc_12": "foo", "abc_12_ext": "bar"},
	}
	// 手工构造 ReverseOrdered：长的在前
	rw.ReverseOrdered = [][2]string{
		{"abc_12_ext", "bar"},
		{"abc_12", "foo"},
	}
	data := []byte(`{"tool":"abc_12_ext","other":"abc_12"}`)
	restored := string(restoreToolNamesInBytes(data, rw))
	require.Equal(t, `{"tool":"bar","other":"foo"}`, restored)
}

func TestRestoreToolNamesInBytes_StaticPrefixRollback(t *testing.T) {
	data := []byte(`{"name":"sessions_list","id":"cc_ses_xyz"}`)
	got := string(restoreToolNamesInBytes(data, nil))
	require.Equal(t, `{"name":"sessions_list","id":"session_xyz"}`, got)
}

func TestToolNameRewrite_KnownLowercaseToolsBecomeTitleCase(t *testing.T) {
	knownTools := []struct {
		lower string
		title string
	}{
		{"bash", "Bash"},
		{"read", "Read"},
		{"write", "Write"},
		{"edit", "Edit"},
		{"glob", "Glob"},
		{"grep", "Grep"},
		{"task", "Task"},
		{"webfetch", "WebFetch"},
		{"todowrite", "TodoWrite"},
		{"question", "Question"},
		{"skill", "Skill"},
		{"ls", "LS"},
		{"todoread", "TodoRead"},
		{"notebookedit", "NotebookEdit"},
	}

	var bodyJSON strings.Builder
	bodyJSON.WriteString(`{"tools":[`)
	for i, tool := range knownTools {
		if i > 0 {
			bodyJSON.WriteByte(',')
		}
		_, _ = fmt.Fprintf(&bodyJSON, `{"name":%q,"input_schema":{}}`, tool.lower)
	}
	bodyJSON.WriteString(`]}`)
	body := []byte(bodyJSON.String())

	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	require.Len(t, rw.Forward, len(knownTools))

	out := applyToolNameRewriteToBody(body, rw)

	for i, tool := range knownTools {
		path := fmt.Sprintf("tools.%d.name", i)
		require.Equal(t, tool.title, gjson.GetBytes(out, path).String())
		require.Equal(t, tool.title, rw.Forward[tool.lower])
		require.Equal(t, tool.lower, rw.Reverse[tool.title])
	}
}

func TestToolNameRewrite_TitleCaseInputsPreservedAndNotReverseCorrupted(t *testing.T) {
	body := []byte(`{"tools":[{"name":"Bash","input_schema":{}},{"name":"glob","input_schema":{}}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	require.NotContains(t, rw.Forward, "Bash")
	require.NotContains(t, rw.Reverse, "Bash")
	require.Equal(t, "Glob", rw.Forward["glob"])

	out := applyToolNameRewriteToBody(body, rw)
	require.Equal(t, "Bash", gjson.GetBytes(out, "tools.0.name").String())
	require.Equal(t, "Glob", gjson.GetBytes(out, "tools.1.name").String())

	restored := restoreToolNamesInBytes([]byte(`{"content":[{"type":"tool_use","name":"Bash"},{"type":"tool_use","name":"Glob"}]}`), rw)
	require.Equal(t, "Bash", gjson.GetBytes(restored, "content.0.name").String())
	require.Equal(t, "glob", gjson.GetBytes(restored, "content.1.name").String())
}

func TestToolNameRewrite_UnknownCustomToolsStayUnchanged(t *testing.T) {
	body := []byte(`{"tools":[{"name":"custom_alpha","input_schema":{}},{"name":"custom_beta","input_schema":{}},{"name":"custom_gamma","input_schema":{}},{"name":"custom_delta","input_schema":{}},{"name":"custom_epsilon","input_schema":{}},{"name":"custom_zeta","input_schema":{}}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.Nil(t, rw)

	out := applyToolNameRewriteToBody(body, rw)
	require.Equal(t, "custom_alpha", gjson.GetBytes(out, "tools.0.name").String())
	require.Equal(t, "custom_zeta", gjson.GetBytes(out, "tools.5.name").String())
}

func TestToolNameRewrite_ServerTypedToolsStayUnchanged(t *testing.T) {
	body := []byte(`{"tools":[{"name":"webfetch","type":"web_search_20250305"},{"name":"bash","input_schema":{}}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	require.Equal(t, "Bash", rw.Forward["bash"])
	require.NotContains(t, rw.Forward, "webfetch")

	out := applyToolNameRewriteToBody(body, rw)
	require.Equal(t, "webfetch", gjson.GetBytes(out, "tools.0.name").String())
	require.Equal(t, "Bash", gjson.GetBytes(out, "tools.1.name").String())
}

func TestToolNameRewrite_ToolChoiceAndHistoricalToolUseConsistent(t *testing.T) {
	body := []byte(`{"tools":[{"name":"bash","input_schema":{}},{"name":"read","input_schema":{}}],"tool_choice":{"type":"tool","name":"bash"},"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu_bash","name":"bash","input":{}},{"type":"tool_use","id":"tu_read","name":"read","input":{}},{"type":"text","text":"done"}]}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)

	out := applyToolNameRewriteToBody(body, rw)

	require.Equal(t, "Bash", gjson.GetBytes(out, "tools.0.name").String())
	require.Equal(t, "Read", gjson.GetBytes(out, "tools.1.name").String())
	require.Equal(t, "Bash", gjson.GetBytes(out, "tool_choice.name").String())
	require.Equal(t, "Bash", gjson.GetBytes(out, "messages.0.content.0.name").String())
	require.Equal(t, "Read", gjson.GetBytes(out, "messages.0.content.1.name").String())
	require.Equal(t, "done", gjson.GetBytes(out, "messages.0.content.2.text").String())
}

func TestToolNameRewrite_CollisionSuffixDeterministicAndReversible(t *testing.T) {
	body := []byte(`{"tools":[{"name":"Bash","input_schema":{}},{"name":"bash","input_schema":{}}],"tool_choice":{"type":"tool","name":"bash"},"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu_lower","name":"bash","input":{}},{"type":"tool_use","id":"tu_title","name":"Bash","input":{}}]}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	rwAgain := buildToolNameRewriteFromBody(body)
	require.Equal(t, rw.Forward, rwAgain.Forward)

	fakeBash := rw.Forward["bash"]
	require.Regexp(t, `^Bash_[0-9a-f]{6}$`, fakeBash)
	require.Regexp(t, `^[A-Za-z0-9_-]+$`, fakeBash)
	require.NotContains(t, rw.Forward, "Bash")
	require.NotContains(t, rw.Reverse, "Bash")
	require.Equal(t, "bash", rw.Reverse[fakeBash])

	out := applyToolNameRewriteToBody(body, rw)
	require.Equal(t, "Bash", gjson.GetBytes(out, "tools.0.name").String())
	require.Equal(t, fakeBash, gjson.GetBytes(out, "tools.1.name").String())
	require.Equal(t, fakeBash, gjson.GetBytes(out, "tool_choice.name").String())
	require.Equal(t, fakeBash, gjson.GetBytes(out, "messages.0.content.0.name").String())
	require.Equal(t, "Bash", gjson.GetBytes(out, "messages.0.content.1.name").String())

	response := []byte(`{"content":[{"type":"tool_use","name":"Bash"},{"type":"tool_use","name":"` + fakeBash + `"}]}`)
	restored := restoreToolNamesInBytes(response, rw)
	require.Equal(t, "Bash", gjson.GetBytes(restored, "content.0.name").String())
	require.Equal(t, "bash", gjson.GetBytes(restored, "content.1.name").String())
}

func TestApplyToolNameRewriteToBody_RenamesToolsAndToolChoice(t *testing.T) {
	body := []byte(`{"tools":[{"name":"bash","input_schema":{}},{"name":"read","input_schema":{}},{"name":"web_search","type":"web_search_20250305"}],"tool_choice":{"type":"tool","name":"bash"}}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	require.Contains(t, rw.Forward, "bash")
	require.Contains(t, rw.Forward, "read")
	// web_search 是 server tool，不参与工具名改写
	require.NotContains(t, rw.Forward, "web_search")

	out := applyToolNameRewriteToBody(body, rw)

	// tools[0].name 和 tools[1].name 被改写，tools[2].name 保持不变
	require.Equal(t, "Bash", gjson.GetBytes(out, "tools.0.name").String())
	require.Equal(t, "Read", gjson.GetBytes(out, "tools.1.name").String())
	require.Equal(t, "web_search", gjson.GetBytes(out, "tools.2.name").String())

	// tool_choice.name 被同步改写
	require.Equal(t, "Bash", gjson.GetBytes(out, "tool_choice.name").String())
	require.Equal(t, "tool", gjson.GetBytes(out, "tool_choice.type").String())
}

func TestApplyToolNameRewriteToBody_RenamesToolUseInMessages(t *testing.T) {
	// bash 通过已知工具映射改写为 Bash
	// web_search 是 server tool（type != ""），不参与工具名改写
	// messages 中的 tool_use.name 必须同步改写，才能和 tools[] 保持一致
	body := []byte(`{"tools":[{"name":"bash","input_schema":{}},{"name":"web_search","type":"web_search_20250305"}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]},{"role":"assistant","content":[{"type":"tool_use","id":"tu_01","name":"bash","input":{}},{"type":"text","text":"thinking"}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_01","content":"ok"}]}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	require.Equal(t, "Bash", rw.Forward["bash"])

	out := applyToolNameRewriteToBody(body, rw)

	// tools[0].name 被改写
	require.Equal(t, "Bash", gjson.GetBytes(out, "tools.0.name").String())
	// tools[1].name 是 server tool，保持不变
	require.Equal(t, "web_search", gjson.GetBytes(out, "tools.1.name").String())
	// messages[1].content[0].name 是 tool_use，必须同步改写以匹配 tools[]
	require.Equal(t, "Bash", gjson.GetBytes(out, "messages.1.content.0.name").String())
	// messages[1].content[1] 是 text，保持不变
	require.Equal(t, "thinking", gjson.GetBytes(out, "messages.1.content.1.text").String())
	// messages[2].content[0] 是 tool_result，不包含 name 字段，保持不变
	require.Equal(t, "ok", gjson.GetBytes(out, "messages.2.content.0.content").String())
}

func TestApplyToolNameRewriteToBody_UnknownDynamicCandidatesStayUnchanged(t *testing.T) {
	body := []byte(`{"tools":[{"name":"alpha_search","input_schema":{}},{"name":"beta_lookup","input_schema":{}},{"name":"gamma_fetch","input_schema":{}},{"name":"delta_update","input_schema":{}},{"name":"epsilon_parse","input_schema":{}},{"name":"zeta_render","input_schema":{}},{"name":"web_search","type":"web_search_20250305"}],"tool_choice":{"type":"tool","name":"gamma_fetch"},"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu_dyn","name":"gamma_fetch","input":{}},{"type":"tool_use","id":"tu_srv","name":"web_search","input":{}},{"type":"text","text":"done"}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_dyn","content":"ok"}]}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.Nil(t, rw)

	out := applyToolNameRewriteToBody(body, rw)

	// 未知自定义工具不再触发 Parrot 动态假名映射
	require.Equal(t, "gamma_fetch", gjson.GetBytes(out, "tools.2.name").String())
	require.Equal(t, "gamma_fetch", gjson.GetBytes(out, "tool_choice.name").String())
	require.Equal(t, "gamma_fetch", gjson.GetBytes(out, "messages.0.content.0.name").String())
	// server tool 不参与映射，历史 tool_use 中同名引用也保持不变
	require.Equal(t, "web_search", gjson.GetBytes(out, "tools.6.name").String())
	require.Equal(t, "web_search", gjson.GetBytes(out, "messages.0.content.1.name").String())
	// tool_result 依靠 tool_use_id 关联，不需要 name 字段
	require.Equal(t, "ok", gjson.GetBytes(out, "messages.1.content.0.content").String())
}

func TestApplyToolsLastCacheBreakpoint_InjectsDefault(t *testing.T) {
	body := []byte(`{"tools":[{"name":"a","input_schema":{}},{"name":"b","input_schema":{}}]}`)
	out := applyToolsLastCacheBreakpoint(body)
	require.Equal(t, "ephemeral", gjson.GetBytes(out, "tools.1.cache_control.type").String())
	require.Equal(t, "5m", gjson.GetBytes(out, "tools.1.cache_control.ttl").String())
	// First tool untouched
	require.False(t, gjson.GetBytes(out, "tools.0.cache_control").Exists())
}

func TestApplyToolsLastCacheBreakpoint_PassesThroughClientTTL(t *testing.T) {
	body := []byte(`{"tools":[{"name":"a","input_schema":{},"cache_control":{"type":"ephemeral","ttl":"1h"}}]}`)
	out := applyToolsLastCacheBreakpoint(body)
	// User-provided ttl must be preserved.
	require.Equal(t, "1h", gjson.GetBytes(out, "tools.0.cache_control.ttl").String())
}

func TestStripMessageCacheControl(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`)
	out := stripMessageCacheControl(body)
	require.False(t, gjson.GetBytes(out, "messages.0.content.0.cache_control").Exists())
}

func TestAddMessageCacheBreakpoints_LastMessageOnly(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	out := addMessageCacheBreakpoints(body)
	require.Equal(t, "ephemeral", gjson.GetBytes(out, "messages.0.content.0.cache_control.type").String())
	require.Equal(t, "5m", gjson.GetBytes(out, "messages.0.content.0.cache_control.ttl").String())
}

func TestAddMessageCacheBreakpoints_SecondToLastUserTurn(t *testing.T) {
	// Parrot 不变量：messages ≥ 4 时才打第二个断点，且位置是"倒数第二个 user turn"。
	body := []byte(`{"messages":[
        {"role":"user","content":[{"type":"text","text":"q1"}]},
        {"role":"assistant","content":[{"type":"text","text":"a1"}]},
        {"role":"user","content":[{"type":"text","text":"q2"}]},
        {"role":"assistant","content":[{"type":"text","text":"a2"}]}
    ]}`)
	out := addMessageCacheBreakpoints(body)
	// 最后一条 assistant 被打断点
	require.Equal(t, "ephemeral", gjson.GetBytes(out, "messages.3.content.0.cache_control.type").String())
	// 倒数第二个 user turn = index 0（唯一另一个 user）
	require.Equal(t, "ephemeral", gjson.GetBytes(out, "messages.0.content.0.cache_control.type").String())
	// 其他不打断点
	require.False(t, gjson.GetBytes(out, "messages.1.content.0.cache_control").Exists())
	require.False(t, gjson.GetBytes(out, "messages.2.content.0.cache_control").Exists())
}

func TestAddMessageCacheBreakpoints_StringContentPromoted(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	out := addMessageCacheBreakpoints(body)
	// content 升级成数组
	require.True(t, gjson.GetBytes(out, "messages.0.content").IsArray())
	require.Equal(t, "text", gjson.GetBytes(out, "messages.0.content.0.type").String())
	require.Equal(t, "hi", gjson.GetBytes(out, "messages.0.content.0.text").String())
	require.Equal(t, "5m", gjson.GetBytes(out, "messages.0.content.0.cache_control.ttl").String())
}

func TestRewriteMessageCacheControlIfEnabled_DefaultKeepsClientAnchors(t *testing.T) {
	body := []byte(`{"messages":[
		{"role":"user","content":[{"type":"text","text":"stable","cache_control":{"type":"ephemeral","ttl":"1h"}}]},
		{"role":"assistant","content":[{"type":"text","text":"ok"}]},
		{"role":"user","content":[{"type":"text","text":"latest","cache_control":{"type":"ephemeral","ttl":"5m"}}]}
	]}`)

	out := (&GatewayService{}).rewriteMessageCacheControlIfEnabled(context.Background(), body)

	require.JSONEq(t, string(body), string(out))
	require.Equal(t, "1h", gjson.GetBytes(out, "messages.0.content.0.cache_control.ttl").String())
	require.Equal(t, "5m", gjson.GetBytes(out, "messages.2.content.0.cache_control.ttl").String())
}

func TestRewriteMessageCacheControlIfEnabled_OptInPreservesLegacyRewrite(t *testing.T) {
	body := []byte(`{"messages":[
		{"role":"user","content":[{"type":"text","text":"stable","cache_control":{"type":"ephemeral","ttl":"1h"}}]},
		{"role":"assistant","content":[{"type":"text","text":"ok"}]},
		{"role":"user","content":[{"type":"text","text":"latest","cache_control":{"type":"ephemeral","ttl":"1h"}}]},
		{"role":"assistant","content":[{"type":"text","text":"done"}]}
	]}`)
	repo := &gatewayTTLSettingRepo{data: map[string]string{
		SettingKeyRewriteMessageCacheControl: "true",
	}}
	gatewayForwardingCache.Store(&cachedGatewayForwardingSettings{})
	svc := &GatewayService{settingService: NewSettingService(repo, &config.Config{})}

	out := svc.rewriteMessageCacheControlIfEnabled(context.Background(), body)

	require.Equal(t, "5m", gjson.GetBytes(out, "messages.0.content.0.cache_control.ttl").String())
	require.False(t, gjson.GetBytes(out, "messages.2.content.0.cache_control").Exists())
	require.Equal(t, "5m", gjson.GetBytes(out, "messages.3.content.0.cache_control.ttl").String())
}

func TestBuildToolNameRewriteFromBody_ReverseOrderedByLengthDesc(t *testing.T) {
	// 已知工具映射会生成 request-local reverse map，验证 ReverseOrdered 按假名长度倒序排列。
	body := []byte(`{"tools":[
        {"name":"bash","input_schema":{}},
        {"name":"todowrite","input_schema":{}},
        {"name":"notebookedit","input_schema":{}}
    ]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	require.NotEmpty(t, rw.ReverseOrdered)
	for i := 1; i < len(rw.ReverseOrdered); i++ {
		require.GreaterOrEqual(t, len(rw.ReverseOrdered[i-1][0]), len(rw.ReverseOrdered[i][0]),
			"ReverseOrdered must be sorted by fake-name length descending")
	}
}

func TestRestoreToolNamesInBytes_NoMapping_NoStaticMatch_IsNoop(t *testing.T) {
	data := []byte("plain text without any tool names")
	require.Equal(t, string(data), string(restoreToolNamesInBytes(data, nil)))
}

func TestReverseToolNamesIfPresent_ToolResponseJSONUsesRequestLocalMap(t *testing.T) {
	body := []byte(`{"tools":[{"name":"bash","input_schema":{}},{"name":"read","input_schema":{}}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)

	response := []byte(`{"content":[{"type":"tool_use","name":"Bash"},{"type":"tool_use","name":"Read"},{"type":"tool_use","name":"Write"}]}`)
	restored := reverseToolNamesIfPresent(newToolNameRewriteTestContext(rw), response)

	require.Equal(t, "bash", gjson.GetBytes(restored, "content.0.name").String())
	require.Equal(t, "read", gjson.GetBytes(restored, "content.1.name").String())
	require.Equal(t, "Write", gjson.GetBytes(restored, "content.2.name").String())
}

func TestReverseToolNamesIfPresent_ToolResponseStreamingLinesUseRequestLocalMap(t *testing.T) {
	body := []byte(`{"tools":[{"name":"bash","input_schema":{}},{"name":"read","input_schema":{}}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)

	chatCompletionLine := []byte(`data: {"choices":[{"delta":{"tool_calls":[{"type":"function","function":{"name":"Bash","arguments":"{}"}}]}}]}` + "\n\n")
	responsesLine := []byte(`data: {"type":"response.output_item.added","item":{"type":"function_call","name":"Read","arguments":"{}"}}` + "\n\n")

	chatRestored := reverseToolNamesIfPresent(newToolNameRewriteTestContext(rw), chatCompletionLine)
	responsesRestored := reverseToolNamesIfPresent(newToolNameRewriteTestContext(rw), responsesLine)

	require.Contains(t, string(chatRestored), `"name":"bash"`)
	require.NotContains(t, string(chatRestored), `"name":"Bash"`)
	require.Contains(t, string(responsesRestored), `"name":"read"`)
	require.NotContains(t, string(responsesRestored), `"name":"Read"`)
}

func TestReverseToolNamesIfPresent_ToolResponseMixedTitleCaseDoesNotCorruptClientNames(t *testing.T) {
	body := []byte(`{"tools":[{"name":"Bash","input_schema":{}},{"name":"glob","input_schema":{}}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	require.NotContains(t, rw.Reverse, "Bash")
	require.Equal(t, "glob", rw.Reverse["Glob"])

	response := []byte(`{"content":[{"type":"tool_use","name":"Bash"},{"type":"tool_use","name":"Glob"}]}`)
	restored := reverseToolNamesIfPresent(newToolNameRewriteTestContext(rw), response)

	require.Equal(t, "Bash", gjson.GetBytes(restored, "content.0.name").String())
	require.Equal(t, "glob", gjson.GetBytes(restored, "content.1.name").String())
}

func TestReverseToolNamesIfPresent_ToolResponseCollisionSuffixRestoresOriginalName(t *testing.T) {
	body := []byte(`{"tools":[{"name":"Bash","input_schema":{}},{"name":"bash","input_schema":{}}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	fakeName := rw.Forward["bash"]
	require.Regexp(t, `^Bash_[0-9a-f]{6}$`, fakeName)

	response := []byte(`{"content":[{"type":"tool_use","name":"Bash"},{"type":"tool_use","name":"` + fakeName + `"}]}`)
	restored := reverseToolNamesIfPresent(newToolNameRewriteTestContext(rw), response)

	require.Equal(t, "Bash", gjson.GetBytes(restored, "content.0.name").String())
	require.Equal(t, "bash", gjson.GetBytes(restored, "content.1.name").String())
}

func TestReverseToolNamesIfPresent_ToolResponseDoesNotRenameUnmappedTitleCase(t *testing.T) {
	body := []byte(`{"tools":[{"name":"bash","input_schema":{}}]}`)
	rw := buildToolNameRewriteFromBody(body)
	require.NotNil(t, rw)
	require.NotContains(t, rw.Reverse, "Read")

	response := []byte(`{"content":[{"type":"tool_use","name":"Read"},{"type":"tool_use","name":"Bash"}]}`)
	restored := reverseToolNamesIfPresent(newToolNameRewriteTestContext(rw), response)

	require.Equal(t, "Read", gjson.GetBytes(restored, "content.0.name").String())
	require.Equal(t, "bash", gjson.GetBytes(restored, "content.1.name").String())
}

func TestReverseToolNamesIfPresent_ToolResponseConcurrentContextsAreIsolated(t *testing.T) {
	bashRewrite := buildToolNameRewriteFromBody([]byte(`{"tools":[{"name":"bash","input_schema":{}}]}`))
	readRewrite := buildToolNameRewriteFromBody([]byte(`{"tools":[{"name":"read","input_schema":{}}]}`))
	require.NotNil(t, bashRewrite)
	require.NotNil(t, readRewrite)

	bashContext := newToolNameRewriteTestContext(bashRewrite)
	readContext := newToolNameRewriteTestContext(readRewrite)
	response := []byte(`{"content":[{"type":"tool_use","name":"Bash"},{"type":"tool_use","name":"Read"}]}`)

	var waitGroup sync.WaitGroup
	errors := make(chan error, 40)
	for range 20 {
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			restored := reverseToolNamesIfPresent(bashContext, response)
			if got := gjson.GetBytes(restored, "content.0.name").String(); got != "bash" {
				errors <- fmt.Errorf("bash context restored first tool as %q", got)
			}
			if got := gjson.GetBytes(restored, "content.1.name").String(); got != "Read" {
				errors <- fmt.Errorf("bash context cross-restored second tool as %q", got)
			}
		}()
		go func() {
			defer waitGroup.Done()
			restored := reverseToolNamesIfPresent(readContext, response)
			if got := gjson.GetBytes(restored, "content.0.name").String(); got != "Bash" {
				errors <- fmt.Errorf("read context cross-restored first tool as %q", got)
			}
			if got := gjson.GetBytes(restored, "content.1.name").String(); got != "read" {
				errors <- fmt.Errorf("read context restored second tool as %q", got)
			}
		}()
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}
