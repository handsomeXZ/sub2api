package service

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// toolNameRewriteKey 是 gin.Context 上存 ToolNameRewrite 映射的 key。
// 请求阶段写入，响应阶段读取，用于 bytes 级逆向还原假名 → 真名。
const toolNameRewriteKey = "claude_tool_name_rewrite"

// staticToolNameRewrites 是历史 Parrot 前缀映射；主请求重写不再使用它，
// 仅在响应还原阶段作为弱兼容保留。
var staticToolNameRewrites = map[string]string{
	"sessions_": "cc_sess_",
	"session_":  "cc_ses_",
}

// knownToolTitleCaseRewrites maps known Claude Code/OpenCode tool names to the
// official Claude Code TitleCase names used on OAuth traffic.
var knownToolTitleCaseRewrites = map[string]string{
	"bash":         "Bash",
	"read":         "Read",
	"write":        "Write",
	"edit":         "Edit",
	"glob":         "Glob",
	"grep":         "Grep",
	"task":         "Task",
	"webfetch":     "WebFetch",
	"todowrite":    "TodoWrite",
	"question":     "Question",
	"skill":        "Skill",
	"ls":           "LS",
	"todoread":     "TodoRead",
	"notebookedit": "NotebookEdit",
}

// ToolNameRewrite 是单次请求内的工具名混淆映射。
//   - Forward: real → fake，请求阶段在 body 上应用。
//   - Reverse: fake → real，响应阶段对每个 chunk 做 bytes.Replace 还原。
//
// ReverseOrdered 是按假名长度倒序的 (fake, real) 列表，用于防止短假名是长假名的
// 子串时 bytes.Replace 先被吃掉（对齐 Parrot _restore_tool_names_in_chunk 的
// `sorted(..., key=lambda x: len(x[1]), reverse=True)`）。
type ToolNameRewrite struct {
	Forward        map[string]string
	Reverse        map[string]string
	ReverseOrdered [][2]string
}

// shouldMimicToolName 指示某个 tool 是否需要重命名。
// server tool（type != "" 且不是 "function" / "custom"）是 Anthropic 协议语义的一部分，
// 比如 "web_search_20250305" / "computer_20250124"；误改会导致上游拒绝。
func shouldMimicToolName(toolType string) bool {
	if toolType == "" || toolType == "function" || toolType == "custom" {
		return true
	}
	return false
}

func buildKnownToolTitleCaseMap(mimicableNames, allToolNames []string, occupied map[string]struct{}) map[string]string {
	if len(mimicableNames) == 0 {
		return nil
	}

	groups := make(map[string][]string)
	seen := make(map[string]struct{})
	for _, name := range mimicableNames {
		target, ok := knownToolTitleCaseRewrites[name]
		if !ok || target == name {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		groups[target] = append(groups[target], name)
	}
	if len(groups) == 0 {
		return nil
	}

	toolSetKey := stableToolSetKey(allToolNames)
	targets := make([]string, 0, len(groups))
	for target := range groups {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	mapping := make(map[string]string)
	for _, target := range targets {
		originals := groups[target]
		sort.Strings(originals)
		_, targetOccupied := occupied[target]
		suffixAll := targetOccupied || len(originals) > 1
		for i, original := range originals {
			fake := target
			if suffixAll || i > 0 {
				fake = uniqueToolNameWithSuffix(target, original, toolSetKey, occupied)
			}
			mapping[original] = fake
			occupied[fake] = struct{}{}
		}
	}
	return mapping
}

func stableToolSetKey(names []string) string {
	seen := make(map[string]struct{}, len(names))
	unique := make([]string, 0, len(names))
	for _, name := range names {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		unique = append(unique, name)
	}
	sort.Strings(unique)
	return strings.Join(unique, "\x00")
}

func uniqueToolNameWithSuffix(base, original, toolSetKey string, occupied map[string]struct{}) string {
	for attempt := 0; ; attempt++ {
		candidate := base + toolNameCollisionSuffix(original, toolSetKey, attempt)
		if _, exists := occupied[candidate]; !exists {
			return candidate
		}
	}
}

func toolNameCollisionSuffix(original, toolSetKey string, attempt int) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(original))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(toolSetKey))
	if attempt > 0 {
		_, _ = h.Write([]byte{0})
		_, _ = fmt.Fprintf(h, "%d", attempt)
	}
	return fmt.Sprintf("_%06x", h.Sum32()&0xffffff)
}

// buildToolNameRewriteFromBody 扫描 body 的 tools[*].name，构造 ToolNameRewrite
// 并返回它。主路径只把已知/官方工具名改成 Claude Code TitleCase；未知工具保持不变。
//
// 注意：只扫描，不改 body。真正的 body 改写在 applyToolNameRewriteToBody。
func buildToolNameRewriteFromBody(body []byte) *ToolNameRewrite {
	tools := gjson.GetBytes(body, "tools")
	if !tools.IsArray() {
		return nil
	}

	mimicableNames := make([]string, 0)
	allToolNames := make([]string, 0)
	occupiedNames := make(map[string]struct{})
	toolsArr := tools.Array()
	for _, t := range toolsArr {
		name := t.Get("name").String()
		if name == "" {
			continue
		}
		allToolNames = append(allToolNames, name)
		if !shouldMimicToolName(t.Get("type").String()) {
			occupiedNames[name] = struct{}{}
			continue
		}
		mimicableNames = append(mimicableNames, name)
		if target, ok := knownToolTitleCaseRewrites[name]; !ok || target == name {
			occupiedNames[name] = struct{}{}
		}
	}

	titleCaseMap := buildKnownToolTitleCaseMap(mimicableNames, allToolNames, occupiedNames)
	if len(titleCaseMap) == 0 {
		return nil
	}

	rw := &ToolNameRewrite{
		Forward: make(map[string]string),
		Reverse: make(map[string]string),
	}
	for name, fake := range titleCaseMap {
		if fake == name {
			continue
		}
		rw.Forward[name] = fake
		rw.Reverse[fake] = name
	}
	if len(rw.Forward) == 0 {
		return nil
	}

	rw.ReverseOrdered = make([][2]string, 0, len(rw.Reverse))
	for fake, real := range rw.Reverse {
		rw.ReverseOrdered = append(rw.ReverseOrdered, [2]string{fake, real})
	}
	sort.SliceStable(rw.ReverseOrdered, func(i, j int) bool {
		if len(rw.ReverseOrdered[i][0]) == len(rw.ReverseOrdered[j][0]) {
			return rw.ReverseOrdered[i][0] < rw.ReverseOrdered[j][0]
		}
		return len(rw.ReverseOrdered[i][0]) > len(rw.ReverseOrdered[j][0])
	})

	return rw
}

// applyToolNameRewriteToBody 把已构造的 ToolNameRewrite 应用到 body 上：
//
//   - 改写 $.tools[*].name（仅对 shouldMimicToolName 通过的 tool）
//   - 改写 $.tool_choice.name（仅当 $.tool_choice.type == "tool"）
//   - 改写 $.messages[*].content[*].name（仅当 type == "tool_use"）
//   - 在 $.tools[last].cache_control 上打 ephemeral 缓存断点
//
// 响应侧 bytes.Replace 会连带还原假名 → 真名。
func applyToolNameRewriteToBody(body []byte, rw *ToolNameRewrite) []byte {
	if rw == nil || len(rw.Forward) == 0 {
		body = applyToolsLastCacheBreakpoint(body)
		return body
	}

	tools := gjson.GetBytes(body, "tools")
	if tools.IsArray() {
		idx := -1
		tools.ForEach(func(_, t gjson.Result) bool {
			idx++
			if !shouldMimicToolName(t.Get("type").String()) {
				return true
			}
			name := t.Get("name").String()
			if name == "" {
				return true
			}
			fake, ok := rw.Forward[name]
			if !ok {
				return true
			}
			if next, err := sjson.SetBytes(body, fmt.Sprintf("tools.%d.name", idx), fake); err == nil {
				body = next
			}
			return true
		})
	}

	if tc := gjson.GetBytes(body, "tool_choice"); tc.Exists() && tc.Get("type").String() == "tool" {
		name := tc.Get("name").String()
		if fake, ok := rw.Forward[name]; ok {
			if next, err := sjson.SetBytes(body, "tool_choice.name", fake); err == nil {
				body = next
			}
		}
	}

	// 同步改写历史消息中的 tool_use.name，确保它和 tools[] 中的假名一致。
	// 否则 Anthropic 会因为 tool_use 引用了未声明的原始工具名而拒绝请求。
	messages := gjson.GetBytes(body, "messages")
	if messages.IsArray() {
		messages.ForEach(func(msgKey, msg gjson.Result) bool {
			msgIdx := int(msgKey.Num)
			content := msg.Get("content")
			if !content.IsArray() {
				return true
			}
			content.ForEach(func(blkKey, blk gjson.Result) bool {
				blkIdx := int(blkKey.Num)
				if blk.Get("type").String() != "tool_use" {
					return true
				}
				name := blk.Get("name").String()
				if name == "" {
					return true
				}
				if fake, ok := rw.Forward[name]; ok {
					path := fmt.Sprintf("messages.%d.content.%d.name", msgIdx, blkIdx)
					if next, err := sjson.SetBytes(body, path, fake); err == nil {
						body = next
					}
				}
				return true
			})
			return true
		})
	}

	body = applyToolsLastCacheBreakpoint(body)
	return body
}

// applyToolsLastCacheBreakpoint 在 tools 数组最后一个工具上注入 cache_control
// 断点，对齐 Parrot `tools[-1]["cache_control"] = {"type":"ephemeral","ttl":"1h"}`
// 行为，但 ttl 按本仓规则：
//   - 客户端已为该 tool 显式设置 cache_control.ttl → 完全透传不覆盖
//   - 否则注入 {"type":"ephemeral","ttl": claude.DefaultCacheControlTTL}
//
// 纯副作用函数，tools 不存在或为空数组时 no-op。
func applyToolsLastCacheBreakpoint(body []byte) []byte {
	tools := gjson.GetBytes(body, "tools")
	if !tools.IsArray() {
		return body
	}
	arr := tools.Array()
	if len(arr) == 0 {
		return body
	}
	lastIdx := len(arr) - 1
	existingCC := arr[lastIdx].Get("cache_control")

	if existingCC.Exists() && existingCC.Get("ttl").String() != "" {
		return body
	}

	if existingCC.Exists() {
		if next, err := sjson.SetBytes(body, fmt.Sprintf("tools.%d.cache_control.ttl", lastIdx), claude.DefaultCacheControlTTL); err == nil {
			body = next
		}
		return body
	}

	raw := fmt.Sprintf(`{"type":"ephemeral","ttl":%q}`, claude.DefaultCacheControlTTL)
	if next, err := sjson.SetRawBytes(body, fmt.Sprintf("tools.%d.cache_control", lastIdx), []byte(raw)); err == nil {
		body = next
	}
	return body
}

// restoreToolNamesInBytes 对 bytes chunk 做逆向还原：假名 → 真名。
// 按 ReverseOrdered 的假名长度倒序逐个 bytes.Replace，防止子串冲突
// （与 Parrot _restore_tool_names_in_chunk 的 sorted(..., reverse=True) 等价）。
// 再做静态前缀还原（cc_sess_ → sessions_ / cc_ses_ → session_）。
//
// rw 可为 nil；nil 时仍会做静态前缀还原。
func restoreToolNamesInBytes(data []byte, rw *ToolNameRewrite) []byte {
	if rw != nil {
		for _, pair := range rw.ReverseOrdered {
			fake, real := pair[0], pair[1]
			if fake == "" || fake == real {
				continue
			}
			data = replaceAllBytes(data, fake, real)
		}
	}
	for prefix, replacement := range staticToolNameRewrites {
		data = replaceAllBytes(data, replacement, prefix)
	}
	return data
}

// replaceAllBytes 是 bytes.ReplaceAll 的便捷封装，避免每个调用点各自做 []byte 转换。
func replaceAllBytes(data []byte, from, to string) []byte {
	if len(data) == 0 || from == to || !strings.Contains(string(data), from) {
		return data
	}
	return []byte(strings.ReplaceAll(string(data), from, to))
}

// toolNameRewriteFromContext 从 gin.Context 取出请求阶段保存的工具名映射。
// 找不到（c==nil 或 key 不存在或类型不对）时返回 nil；调用方必须能处理 nil。
func toolNameRewriteFromContext(c interface {
	Get(string) (any, bool)
}) *ToolNameRewrite {
	if c == nil {
		return nil
	}
	raw, ok := c.Get(toolNameRewriteKey)
	if !ok || raw == nil {
		return nil
	}
	rw, _ := raw.(*ToolNameRewrite)
	return rw
}

// reverseToolNamesIfPresent 是响应侧 5 处注入点的统一封装：从 c 取出 mapping
// 并对 chunk 做 bytes 级假名→真名替换。c 没有 mapping 时仍会做静态前缀还原。
func reverseToolNamesIfPresent(c interface {
	Get(string) (any, bool)
}, chunk []byte) []byte {
	rw := toolNameRewriteFromContext(c)
	if rw == nil && len(staticToolNameRewrites) == 0 {
		return chunk
	}
	return restoreToolNamesInBytes(chunk, rw)
}
