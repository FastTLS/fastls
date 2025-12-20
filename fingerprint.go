package fastls

// Fingerprint 接口定义了指纹的基本行为
type Fingerprint interface {
	// Type 返回指纹类型，如 "ja3", "ja4r" 等
	Type() string
	// Value 返回指纹的字符串值
	Value() string
	// IsEmpty 检查指纹是否为空
	IsEmpty() bool
}

// Ja3Fingerprint 表示 JA3 指纹
type Ja3Fingerprint struct {
	FingerprintValue string `json:"value"`
}

func (j Ja3Fingerprint) Type() string {
	return "ja3"
}

func (j Ja3Fingerprint) Value() string {
	return j.FingerprintValue
}

func (j Ja3Fingerprint) IsEmpty() bool {
	return j.FingerprintValue == ""
}

// Ja4Fingerprint 表示 JA4R 指纹
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
type Ja4Fingerprint struct {
	FingerprintValue string `json:"value"`
}

// Type 返回指纹类型 "ja4r"
//
// 注意：此功能是实验性的。
// EXPERIMENTAL: This feature is experimental.
func (j Ja4Fingerprint) Type() string {
	return "ja4r"
}

func (j Ja4Fingerprint) Value() string {
	return j.FingerprintValue
}

func (j Ja4Fingerprint) IsEmpty() bool {
	return j.FingerprintValue == ""
}

// GetFingerprintValue 从 Options 中获取指纹值
func (o *Options) GetFingerprintValue() string {
	if o.Fingerprint != nil && !o.Fingerprint.IsEmpty() {
		return o.Fingerprint.Value()
	}
	return ""
}

// GetFingerprintType 从 Options 中获取指纹类型
func (o *Options) GetFingerprintType() string {
	if o.Fingerprint != nil && !o.Fingerprint.IsEmpty() {
		return o.Fingerprint.Type()
	}
	return ""
}

// ValidateFingerprint 验证指纹类型
func (o *Options) ValidateFingerprint() error {
	// JA4R 指纹现在已支持，不再返回错误
	return nil
}

// IsJa3 检查当前使用的是否为 JA3 指纹
func (o *Options) IsJa3() bool {
	return o.GetFingerprintType() == "ja3"
}

// IsJa4 检查当前使用的是否为 JA4R 指纹
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func (o *Options) IsJa4() bool {
	return o.GetFingerprintType() == "ja4r"
}
