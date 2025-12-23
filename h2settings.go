package fastls

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/FastTLS/fhttp/http2"
)

var settings = map[string]http2.SettingID{
	"HEADER_TABLE_SIZE":      http2.SettingHeaderTableSize,
	"ENABLE_PUSH":            http2.SettingEnablePush,
	"MAX_CONCURRENT_STREAMS": http2.SettingMaxConcurrentStreams,
	"INITIAL_WINDOW_SIZE":    http2.SettingInitialWindowSize,
	"MAX_FRAME_SIZE":         http2.SettingMaxFrameSize,
	"MAX_HEADER_LIST_SIZE":   http2.SettingMaxHeaderListSize,
}

// settingIDToName 将 SETTINGS ID 映射到名称
var settingIDToName = map[int]string{
	1: "HEADER_TABLE_SIZE",
	2: "ENABLE_PUSH",
	3: "MAX_CONCURRENT_STREAMS",
	4: "INITIAL_WINDOW_SIZE",
	5: "MAX_FRAME_SIZE",
	6: "MAX_HEADER_LIST_SIZE",
	9: "NO_RFC7540_PRIORITIES", // Safari 使用的扩展设置
}

// settingOrderToID 将顺序字母映射到 SETTINGS ID
// 根据实际观察和测试，字母映射如下：
// m = HEADER_TABLE_SIZE (1) - 在所有浏览器中一致
// a = ENABLE_PUSH (2) - 在 Chrome 中
// s = INITIAL_WINDOW_SIZE (4) - 在所有浏览器中一致
// p = MAX_HEADER_LIST_SIZE (6) 在 Chrome 中，MAX_FRAME_SIZE (5) 在 Firefox 中
// 注意：字母映射可能因浏览器而异，需要根据实际存在的设置来判断
var settingOrderToID = map[string]int{
	"h": 1, // HEADER_TABLE_SIZE
	"e": 2, // ENABLE_PUSH
	"m": 1, // HEADER_TABLE_SIZE (Chrome/Firefox 使用 m 表示)
	"i": 4, // INITIAL_WINDOW_SIZE
	"f": 5, // MAX_FRAME_SIZE
	"a": 2, // ENABLE_PUSH (在 Chrome 的 m,a,s,p 中，a 是第二个，对应 ENABLE_PUSH)
	"s": 4, // INITIAL_WINDOW_SIZE (Chrome/Firefox 使用 s 表示)
	"p": 5, // MAX_FRAME_SIZE 或 MAX_HEADER_LIST_SIZE (根据上下文判断)
	"c": 3, // MAX_CONCURRENT_STREAMS
}

type H2Settings struct {
	//HEADER_TABLE_SIZE
	//ENABLE_PUSH
	//MAX_CONCURRENT_STREAMS
	//INITIAL_WINDOW_SIZE
	//MAX_FRAME_SIZE
	//MAX_HEADER_LIST_SIZE
	Settings map[string]int `json:"Settings"`
	//HEADER_TABLE_SIZE
	//ENABLE_PUSH
	//MAX_CONCURRENT_STREAMS
	//INITIAL_WINDOW_SIZE
	//MAX_FRAME_SIZE
	//MAX_HEADER_LIST_SIZE
	SettingsOrder  []string                 `json:"SettingsOrder"`
	ConnectionFlow int                      `json:"ConnectionFlow"`
	HeaderPriority map[string]interface{}   `json:"HeaderPriority"`
	PriorityFrames []map[string]interface{} `json:"PriorityFrames"`
}

func ToHTTP2Settings(h2Settings *H2Settings) (http2Settings *http2.HTTP2Settings) {
	http2Settings = &http2.HTTP2Settings{
		Settings:       nil,
		ConnectionFlow: 0,
		HeaderPriority: &http2.PriorityParam{},
		PriorityFrames: nil,
	}
	if h2Settings.Settings != nil {
		if h2Settings.SettingsOrder != nil {
			for _, orderKey := range h2Settings.SettingsOrder {
				val := h2Settings.Settings[orderKey]
				if val != 0 || orderKey == "ENABLE_PUSH" {
					var settingID http2.SettingID
					if id, ok := settings[orderKey]; ok {
						settingID = id
					} else if orderKey == "NO_RFC7540_PRIORITIES" {
						// Safari 使用的扩展设置 ID 9
						settingID = http2.SettingID(9)
					} else if strings.HasPrefix(orderKey, "UNKNOWN_SETTING_") {
						// 处理未知设置：从名称中提取 ID
						idStr := strings.TrimPrefix(orderKey, "UNKNOWN_SETTING_")
						if settingIDInt, err := strconv.Atoi(idStr); err == nil {
							settingID = http2.SettingID(settingIDInt)
						} else {
							continue // 跳过无效的设置
						}
					} else {
						continue // 跳过无效的设置
					}
					http2Settings.Settings = append(http2Settings.Settings, http2.Setting{
						ID:  settingID,
						Val: uint32(val),
					})
				}
			}
		} else {
			for id, val := range h2Settings.Settings {
				var settingID http2.SettingID
				if sid, ok := settings[id]; ok {
					settingID = sid
				} else if id == "NO_RFC7540_PRIORITIES" {
					// Safari 使用的扩展设置 ID 9
					settingID = http2.SettingID(9)
				} else if strings.HasPrefix(id, "UNKNOWN_SETTING_") {
					// 处理未知设置：从名称中提取 ID
					idStr := strings.TrimPrefix(id, "UNKNOWN_SETTING_")
					if settingIDInt, err := strconv.Atoi(idStr); err == nil {
						settingID = http2.SettingID(settingIDInt)
					} else {
						continue // 跳过无效的设置
					}
				} else {
					continue // 跳过无效的设置
				}
				http2Settings.Settings = append(http2Settings.Settings, http2.Setting{
					ID:  settingID,
					Val: uint32(val),
				})
			}
		}
	}
	if h2Settings.ConnectionFlow != 0 {
		http2Settings.ConnectionFlow = h2Settings.ConnectionFlow
	}
	if h2Settings.HeaderPriority != nil {
		var weight int
		var streamDep int
		w := h2Settings.HeaderPriority["weight"]
		switch w.(type) {
		case int:
			weight = w.(int)
		case float64:
			weight = int(w.(float64))
		}
		s := h2Settings.HeaderPriority["streamDep"]
		switch s.(type) {
		case int:
			streamDep = s.(int)
		case float64:
			streamDep = int(s.(float64))
		}
		var priorityParam *http2.PriorityParam
		if w == nil {
			priorityParam = &http2.PriorityParam{
				StreamDep: uint32(streamDep),
				Exclusive: h2Settings.HeaderPriority["exclusive"].(bool),
			}
		} else {
			priorityParam = &http2.PriorityParam{
				StreamDep: uint32(streamDep),
				Exclusive: h2Settings.HeaderPriority["exclusive"].(bool),
				Weight:    uint8(weight - 1),
			}
		}
		http2Settings.HeaderPriority = priorityParam
	}
	if h2Settings.PriorityFrames != nil {
		for _, frame := range h2Settings.PriorityFrames {
			var weight int
			var streamDep int
			var streamID int
			priorityParamSource := frame["priorityParam"].(map[string]interface{})
			w := priorityParamSource["weight"]
			switch w.(type) {
			case int:
				weight = w.(int)
			case float64:
				weight = int(w.(float64))
			}
			s := priorityParamSource["streamDep"]
			switch s.(type) {
			case int:
				streamDep = s.(int)
			case float64:
				streamDep = int(s.(float64))
			}
			sid := frame["streamID"]
			switch sid.(type) {
			case int:
				streamID = sid.(int)
			case float64:
				streamID = int(sid.(float64))
			}
			var priorityParam http2.PriorityParam
			if w == nil {
				priorityParam = http2.PriorityParam{
					StreamDep: uint32(streamDep),
					Exclusive: priorityParamSource["exclusive"].(bool),
				}
			} else {
				priorityParam = http2.PriorityParam{
					StreamDep: uint32(streamDep),
					Exclusive: priorityParamSource["exclusive"].(bool),
					Weight:    uint8(weight - 1),
				}
			}
			http2Settings.PriorityFrames = append(http2Settings.PriorityFrames, http2.PriorityFrame{
				FrameHeader: http2.FrameHeader{
					StreamID: uint32(streamID),
				},
				PriorityParam: priorityParam,
			})
		}
	}
	return http2Settings
}

// ParseH2SettingsString 解析 HTTP/2 设置字符串格式
// 格式: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
// 扩展格式: "1:65536;2:0;4:6291456;6:262144|15663105|0:256:true|m,a,s,p"
// 第一部分: SETTINGS 帧设置 (ID:VALUE;ID:VALUE;...)
// 第二部分: ConnectionFlow (连接流控窗口大小)
// 第三部分: HeaderPriority (格式: streamDep 或 streamDep:weight:exclusive)
//
//	如果只有 streamDep，会根据 streamDep==0 推断 weight 和 exclusive
//	如果提供完整格式，使用精确值
//
// 第四部分: SETTINGS 顺序 (用逗号分隔的字母，如 m,a,s,p)
// 注意: PriorityFrames 当前不支持在字符串格式中表示，默认为空
func ParseH2SettingsString(s string) (*H2Settings, error) {
	parts := strings.Split(s, "|")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid format: expected at least 2 parts separated by |")
	}

	h2Settings := &H2Settings{
		Settings:       make(map[string]int),
		SettingsOrder:  []string{},
		ConnectionFlow: 0,
		HeaderPriority: nil,
		PriorityFrames: []map[string]interface{}{},
	}

	// 解析第一部分: SETTINGS 帧设置
	settingsPart := parts[0]
	if settingsPart != "" {
		settingPairs := strings.Split(settingsPart, ";")
		for _, pair := range settingPairs {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			kv := strings.Split(pair, ":")
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid setting format: %s", pair)
			}

			settingID, err := strconv.Atoi(strings.TrimSpace(kv[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid setting ID: %s", kv[0])
			}

			settingValue, err := strconv.Atoi(strings.TrimSpace(kv[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid setting value: %s", kv[1])
			}

			settingName, ok := settingIDToName[settingID]
			if !ok {
				// 如果设置 ID 不在标准列表中，使用 UNKNOWN_SETTING_<ID> 作为名称
				// 这样可以支持扩展或未知的设置
				settingName = fmt.Sprintf("UNKNOWN_SETTING_%d", settingID)
			}

			h2Settings.Settings[settingName] = settingValue
		}
	}

	// 解析第二部分: ConnectionFlow
	if len(parts) > 1 && parts[1] != "" {
		connectionFlow, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid connection flow: %s", parts[1])
		}
		h2Settings.ConnectionFlow = connectionFlow
	}

	// 解析第三部分: HeaderPriority
	// 格式1: "0" (只有 streamDep，推断 weight 和 exclusive)
	// 格式2: "0:256:true" (streamDep:weight:exclusive，精确值)
	if len(parts) > 2 && parts[2] != "" {
		priorityPart := strings.TrimSpace(parts[2])
		priorityFields := strings.Split(priorityPart, ":")

		if len(priorityFields) == 1 {
			// 只有 streamDep，推断 weight 和 exclusive
			streamDep, err := strconv.Atoi(strings.TrimSpace(priorityFields[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid stream dep: %s", priorityFields[0])
			}

			// 根据 streamDep 推断 weight 和 exclusive
			exclusive := streamDep == 0
			weight := 42
			if exclusive {
				weight = 256
			}

			h2Settings.HeaderPriority = map[string]interface{}{
				"weight":    weight,
				"streamDep": streamDep,
				"exclusive": exclusive,
			}
		} else if len(priorityFields) >= 3 {
			// 完整格式: streamDep:weight:exclusive
			streamDep, err := strconv.Atoi(strings.TrimSpace(priorityFields[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid stream dep: %s", priorityFields[0])
			}

			weight, err := strconv.Atoi(strings.TrimSpace(priorityFields[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid weight: %s", priorityFields[1])
			}

			exclusiveStr := strings.TrimSpace(strings.ToLower(priorityFields[2]))
			exclusive := exclusiveStr == "true" || exclusiveStr == "1"

			h2Settings.HeaderPriority = map[string]interface{}{
				"weight":    weight,
				"streamDep": streamDep,
				"exclusive": exclusive,
			}
		} else {
			return nil, fmt.Errorf("invalid header priority format: %s (expected 'streamDep' or 'streamDep:weight:exclusive')", priorityPart)
		}
	}

	// 解析第四部分: SETTINGS 顺序
	// 注意：字母顺序字符串中的字母位置对应实际存在的设置的顺序
	// 例如：m,a,s,p 表示第一个存在的设置、第二个存在的设置、第三个存在的设置、第四个存在的设置
	if len(parts) > 3 && parts[3] != "" {
		orderPart := strings.TrimSpace(parts[3])
		orderLetters := strings.Split(orderPart, ",")

		// 首先收集所有存在的设置，按照 ID 顺序
		existingSettings := make([]struct {
			id   int
			name string
		}, 0)
		// 先收集标准设置（1-6）和已知扩展设置（9）
		orderedIDs := []int{1, 2, 3, 4, 5, 6, 9}
		for _, id := range orderedIDs {
			settingName, ok := settingIDToName[id]
			if !ok {
				settingName = fmt.Sprintf("UNKNOWN_SETTING_%d", id)
			}
			if _, exists := h2Settings.Settings[settingName]; exists {
				existingSettings = append(existingSettings, struct {
					id   int
					name string
				}{id: id, name: settingName})
			}
		}
		// 然后收集未知设置（按 ID 排序）
		unknownSettings := make([]struct {
			id   int
			name string
		}, 0)
		for name := range h2Settings.Settings {
			if strings.HasPrefix(name, "UNKNOWN_SETTING_") {
				idStr := strings.TrimPrefix(name, "UNKNOWN_SETTING_")
				if id, err := strconv.Atoi(idStr); err == nil {
					// 检查是否已经在 existingSettings 中
					found := false
					for _, es := range existingSettings {
						if es.name == name {
							found = true
							break
						}
					}
					if !found {
						unknownSettings = append(unknownSettings, struct {
							id   int
							name string
						}{id: id, name: name})
					}
				}
			}
		}
		// 按 ID 排序未知设置
		for i := 0; i < len(unknownSettings)-1; i++ {
			for j := i + 1; j < len(unknownSettings); j++ {
				if unknownSettings[i].id > unknownSettings[j].id {
					unknownSettings[i], unknownSettings[j] = unknownSettings[j], unknownSettings[i]
				}
			}
		}
		// 将未知设置添加到 existingSettings
		for _, us := range unknownSettings {
			existingSettings = append(existingSettings, us)
		}

		// 如果字母数量与存在的设置数量匹配，按位置映射
		if len(orderLetters) == len(existingSettings) {
			for i, letter := range orderLetters {
				letter = strings.TrimSpace(strings.ToLower(letter))
				if letter == "" {
					continue
				}
				if i < len(existingSettings) {
					settingName := existingSettings[i].name
					// 检查是否已经添加过，避免重复
					found := false
					for _, existing := range h2Settings.SettingsOrder {
						if existing == settingName {
							found = true
							break
						}
					}
					if !found {
						h2Settings.SettingsOrder = append(h2Settings.SettingsOrder, settingName)
					}
				}
			}
		} else {
			// 如果不匹配，使用字母到 ID 的映射
			for _, letter := range orderLetters {
				letter = strings.TrimSpace(strings.ToLower(letter))
				if letter == "" {
					continue
				}

				// 特殊处理：字母 p 可能对应 MAX_FRAME_SIZE (5) 或 MAX_HEADER_LIST_SIZE (6)
				// 根据实际存在的设置来判断
				var settingID int
				var ok bool
				if letter == "p" {
					// 优先检查 MAX_FRAME_SIZE (5)
					if _, exists := h2Settings.Settings["MAX_FRAME_SIZE"]; exists {
						settingID = 5
						ok = true
					} else if _, exists := h2Settings.Settings["MAX_HEADER_LIST_SIZE"]; exists {
						settingID = 6
						ok = true
					} else {
						ok = false
					}
				} else {
					settingID, ok = settingOrderToID[letter]
				}

				if !ok {
					return nil, fmt.Errorf("unknown setting order letter: %s", letter)
				}

				settingName, ok := settingIDToName[settingID]
				if !ok {
					return nil, fmt.Errorf("unknown setting ID for letter %s: %d", letter, settingID)
				}

				// 只有当该设置存在于 Settings 中时才添加到顺序中
				if _, exists := h2Settings.Settings[settingName]; exists {
					// 检查是否已经添加过，避免重复
					found := false
					for _, existing := range h2Settings.SettingsOrder {
						if existing == settingName {
							found = true
							break
						}
					}
					if !found {
						h2Settings.SettingsOrder = append(h2Settings.SettingsOrder, settingName)
					}
				}
			}
		}

		// 如果顺序字符串中没有包含所有存在的设置，补充剩余的设置
		// 按照 ID 顺序添加未在顺序字符串中的设置
		// 首先处理标准设置（1-6）
		orderedIDsForRemaining := []int{1, 2, 3, 4, 5, 6, 9}
		for _, id := range orderedIDsForRemaining {
			settingName, ok := settingIDToName[id]
			if !ok {
				settingName = fmt.Sprintf("UNKNOWN_SETTING_%d", id)
			}
			if _, exists := h2Settings.Settings[settingName]; exists {
				// 检查是否已经在 SettingsOrder 中
				found := false
				for _, existing := range h2Settings.SettingsOrder {
					if existing == settingName {
						found = true
						break
					}
				}
				if !found {
					h2Settings.SettingsOrder = append(h2Settings.SettingsOrder, settingName)
				}
			}
		}
		// 然后处理未知设置（按 ID 排序）
		unknownSettingsRemaining := make([]struct {
			id   int
			name string
		}, 0)
		for name := range h2Settings.Settings {
			if strings.HasPrefix(name, "UNKNOWN_SETTING_") {
				idStr := strings.TrimPrefix(name, "UNKNOWN_SETTING_")
				if id, err := strconv.Atoi(idStr); err == nil {
					// 检查是否已经在 SettingsOrder 中
					found := false
					for _, existing := range h2Settings.SettingsOrder {
						if existing == name {
							found = true
							break
						}
					}
					if !found {
						unknownSettingsRemaining = append(unknownSettingsRemaining, struct {
							id   int
							name string
						}{id: id, name: name})
					}
				}
			}
		}
		// 按 ID 排序未知设置
		for i := 0; i < len(unknownSettingsRemaining)-1; i++ {
			for j := i + 1; j < len(unknownSettingsRemaining); j++ {
				if unknownSettingsRemaining[i].id > unknownSettingsRemaining[j].id {
					unknownSettingsRemaining[i], unknownSettingsRemaining[j] = unknownSettingsRemaining[j], unknownSettingsRemaining[i]
				}
			}
		}
		// 添加未知设置到顺序中
		for _, us := range unknownSettingsRemaining {
			h2Settings.SettingsOrder = append(h2Settings.SettingsOrder, us.name)
		}
	} else {
		// 如果没有提供顺序，按照 ID 顺序排列
		orderedIDs := []int{1, 2, 3, 4, 5, 6}
		for _, id := range orderedIDs {
			settingName, ok := settingIDToName[id]
			if !ok {
				settingName = fmt.Sprintf("UNKNOWN_SETTING_%d", id)
			}
			if _, exists := h2Settings.Settings[settingName]; exists {
				h2Settings.SettingsOrder = append(h2Settings.SettingsOrder, settingName)
			}
		}
		// 处理未知设置（按 ID 排序）
		unknownSettings := make([]struct {
			id   int
			name string
		}, 0)
		for name := range h2Settings.Settings {
			if strings.HasPrefix(name, "UNKNOWN_SETTING_") {
				idStr := strings.TrimPrefix(name, "UNKNOWN_SETTING_")
				if id, err := strconv.Atoi(idStr); err == nil {
					unknownSettings = append(unknownSettings, struct {
						id   int
						name string
					}{id: id, name: name})
				}
			}
		}
		// 按 ID 排序未知设置
		for i := 0; i < len(unknownSettings)-1; i++ {
			for j := i + 1; j < len(unknownSettings); j++ {
				if unknownSettings[i].id > unknownSettings[j].id {
					unknownSettings[i], unknownSettings[j] = unknownSettings[j], unknownSettings[i]
				}
			}
		}
		// 添加未知设置到顺序中
		for _, us := range unknownSettings {
			h2Settings.SettingsOrder = append(h2Settings.SettingsOrder, us.name)
		}
	}

	// 如果 SettingsOrder 为空，但 Settings 不为空，按照 ID 顺序排列
	if len(h2Settings.SettingsOrder) == 0 && len(h2Settings.Settings) > 0 {
		orderedIDs := []int{1, 2, 3, 4, 5, 6}
		for _, id := range orderedIDs {
			settingName := settingIDToName[id]
			if _, exists := h2Settings.Settings[settingName]; exists {
				h2Settings.SettingsOrder = append(h2Settings.SettingsOrder, settingName)
			}
		}
		// 然后处理未知设置（按 ID 排序）
		unknownSettings := make([]struct {
			id   int
			name string
		}, 0)
		for name := range h2Settings.Settings {
			if strings.HasPrefix(name, "UNKNOWN_SETTING_") {
				idStr := strings.TrimPrefix(name, "UNKNOWN_SETTING_")
				if id, err := strconv.Atoi(idStr); err == nil {
					unknownSettings = append(unknownSettings, struct {
						id   int
						name string
					}{id: id, name: name})
				}
			}
		}
		// 按 ID 排序未知设置
		for i := 0; i < len(unknownSettings)-1; i++ {
			for j := i + 1; j < len(unknownSettings); j++ {
				if unknownSettings[i].id > unknownSettings[j].id {
					unknownSettings[i], unknownSettings[j] = unknownSettings[j], unknownSettings[i]
				}
			}
		}
		// 添加未知设置到顺序中
		for _, us := range unknownSettings {
			found := false
			for _, existing := range h2Settings.SettingsOrder {
				if existing == us.name {
					found = true
					break
				}
			}
			if !found {
				h2Settings.SettingsOrder = append(h2Settings.SettingsOrder, us.name)
			}
		}
	}

	return h2Settings, nil
}

// pHeaderOrderMap 将字母映射到伪头部名称
var pHeaderOrderMap = map[string]string{
	"m": ":method",
	"a": ":authority",
	"s": ":scheme",
	"p": ":path",
}

// ParseH2SettingsStringWithPHeaderOrder 解析 HTTP/2 设置字符串格式，并返回 PHeaderOrderKeys
// 格式: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
// 扩展格式: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p||:method,:authority,:scheme,:path"
// 如果字符串中包含 || 分隔符，则 || 后面的部分为 PHeaderOrderKeys（用逗号分隔）
// 如果没有 || 分隔符，但 SETTINGS 顺序字母数量为 4 且都是 m,a,s,p，则自动推导 PHeaderOrderKeys
// 返回: H2Settings 和 PHeaderOrderKeys（如果提供或可推导）
func ParseH2SettingsStringWithPHeaderOrder(s string) (*H2Settings, []string, error) {
	// 检查是否包含 PHeaderOrderKeys（用 || 分隔）
	var pHeaderOrderKeys []string
	var h2SettingsString string

	if strings.Contains(s, "||") {
		parts := strings.SplitN(s, "||", 2)
		h2SettingsString = parts[0]
		if len(parts) > 1 && parts[1] != "" {
			// 解析 PHeaderOrderKeys
			pHeaderOrderStr := strings.TrimSpace(parts[1])
			if pHeaderOrderStr != "" {
				pHeaderOrderKeys = strings.Split(pHeaderOrderStr, ",")
				// 去除每个键的前后空格
				for i, key := range pHeaderOrderKeys {
					pHeaderOrderKeys[i] = strings.TrimSpace(key)
				}
			}
		}
	} else {
		h2SettingsString = s
	}

	// 解析 H2Settings
	h2Settings, err := ParseH2SettingsString(h2SettingsString)
	if err != nil {
		return nil, nil, err
	}

	// 如果没有显式提供 PHeaderOrderKeys，尝试从 SETTINGS 顺序推导
	if len(pHeaderOrderKeys) == 0 {
		// 从字符串中提取 SETTINGS 顺序部分
		parts := strings.Split(h2SettingsString, "|")
		if len(parts) > 3 && parts[3] != "" {
			orderPart := strings.TrimSpace(parts[3])
			orderLetters := strings.Split(orderPart, ",")
			// 如果前4个字母都是 m,a,s,p 中的字母，则推导 PHeaderOrderKeys
			// 即使后面还有其他字母（如 c），只要前4个匹配就可以推导
			if len(orderLetters) >= 4 {
				derived := make([]string, 0, 4)
				allValid := true
				for i := 0; i < 4; i++ {
					letter := strings.TrimSpace(strings.ToLower(orderLetters[i]))
					if pHeader, ok := pHeaderOrderMap[letter]; ok {
						derived = append(derived, pHeader)
					} else {
						allValid = false
						break
					}
				}
				if allValid && len(derived) == 4 {
					pHeaderOrderKeys = derived
				}
			}
		}
	}

	return h2Settings, pHeaderOrderKeys, nil
}
