package fastls

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// ParseJA4R 解析 JA4R 指纹字符串并转换为 uTLS ClientHelloSpec
// JA4R 格式：t13d<num>_<cipher_suites>_<extensions>_<signature_algorithms>
// 例如：t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func ParseJA4R(ja4r string, userAgent string) (*utls.ClientHelloSpec, error) {
	// 验证格式
	if !strings.HasPrefix(ja4r, "t") {
		return nil, fmt.Errorf("JA4R 格式错误: 应该以 't' 开头")
	}

	// 分割各个部分
	parts := strings.Split(ja4r, "_")
	if len(parts) < 4 {
		return nil, fmt.Errorf("JA4R 格式错误: 应该包含至少4个部分（用下划线分隔），得到 %d 个部分", len(parts))
	}

	// 解析第一部分：t13d<num>
	prefix := parts[0]
	if len(prefix) < 5 {
		return nil, fmt.Errorf("JA4R 前缀格式错误: 应该至少5个字符（t13d<num>），得到: %s", prefix)
	}

	// 提取协议类型和 TLS 版本
	// t = TCP, q = QUIC
	protocolType := prefix[0]
	if protocolType != 't' && protocolType != 'q' {
		return nil, fmt.Errorf("JA4R 协议类型错误: 应该是 't' (TCP) 或 'q' (QUIC)，得到: %c", protocolType)
	}

	// 提取 TLS 版本（13 = TLS 1.3）
	tlsVersionStr := prefix[1:3]
	tlsVersion, err := strconv.ParseUint(tlsVersionStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("JA4R TLS 版本解析错误: %v", err)
	}

	// 提取 SNI 指示（d = 存在 SNI, i = 不存在 SNI）
	sniIndicator := prefix[3]
	if sniIndicator != 'd' && sniIndicator != 'i' {
		return nil, fmt.Errorf("JA4R SNI 指示错误: 应该是 'd' (存在) 或 'i' (不存在)，得到: %c", sniIndicator)
	}

	// 解析密码套件列表（第二部分）
	cipherSuitesStr := parts[1]
	cipherSuites := strings.Split(cipherSuitesStr, ",")
	var cipherSuiteIDs []uint16
	for _, cs := range cipherSuites {
		if cs == "" {
			continue
		}
		csID, err := strconv.ParseUint(cs, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("密码套件解析错误 '%s': %v", cs, err)
		}
		cipherSuiteIDs = append(cipherSuiteIDs, uint16(csID))
	}

	// 解析扩展列表（第三部分）
	extensionsStr := parts[2]
	extensions := strings.Split(extensionsStr, ",")
	var extensionIDs []uint16
	for _, ext := range extensions {
		if ext == "" {
			continue
		}
		extID, err := strconv.ParseUint(ext, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("扩展ID解析错误 '%s': %v", ext, err)
		}
		extensionIDs = append(extensionIDs, uint16(extID))
	}

	// 解析签名算法列表（第四部分）
	signatureAlgorithmsStr := parts[3]
	signatureAlgorithms := strings.Split(signatureAlgorithmsStr, ",")
	var signatureAlgorithmsIDs []uint16
	for _, sig := range signatureAlgorithms {
		if sig == "" {
			continue
		}
		sigID, err := strconv.ParseUint(sig, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("签名算法解析错误 '%s': %v", sig, err)
		}
		signatureAlgorithmsIDs = append(signatureAlgorithmsIDs, uint16(sigID))
	}

	// 根据 User-Agent 确定浏览器类型
	browserType := parseUserAgent(userAgent)

	// 检查是否包含 PSK 扩展（扩展ID 41 = 0x0029）
	includePSK := false
	for _, extID := range extensionIDs {
		if extID == 0x0029 { // pre_shared_key
			includePSK = true
			break
		}
	}

	// 构建扩展映射
	extMap := buildTLSExtensionMap(browserType, includePSK)

	// 设置支持的曲线（从扩展中提取）
	var targetCurves []utls.CurveID
	// 查找 supported_groups 扩展（ID 10 = 0x000a）
	for i, extID := range extensionIDs {
		if extID == 0x000a { // supported_groups
			// 如果扩展列表中有 supported_groups，我们需要从扩展映射中获取
			// 或者根据浏览器类型设置默认曲线
			if browserType == chrome {
				targetCurves = append(targetCurves, utls.CurveID(utls.GREASE_PLACEHOLDER))
			}
			// 注意：JA4R 格式中没有直接包含曲线信息，我们需要从扩展中推断
			// 这里使用默认的曲线配置
			break
		}
		_ = i // 避免未使用变量警告
	}

	// 如果没有找到曲线扩展，使用默认配置
	if len(targetCurves) == 0 {
		if browserType == chrome {
			targetCurves = append(targetCurves, utls.CurveID(utls.GREASE_PLACEHOLDER))
		}
		// 添加常用曲线
		targetCurves = append(targetCurves, utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521)
	}

	extMap["10"] = &utls.SupportedCurvesExtension{Curves: targetCurves}

	// 设置点格式（从扩展中提取）
	var targetPointFormats []byte
	// 查找 ec_point_formats 扩展（ID 11 = 0x000b）
	for _, extID := range extensionIDs {
		if extID == 0x000b { // ec_point_formats
			// 默认点格式
			targetPointFormats = []byte{0x00, 0x01, 0x02}
			break
		}
	}
	if len(targetPointFormats) == 0 {
		targetPointFormats = []byte{0x00, 0x01, 0x02}
	}
	extMap["11"] = &utls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// 设置支持的版本扩展（扩展ID 43 = 0x002b）
	// 根据 TLS 版本设置支持的版本列表
	var supportedVersions []uint16
	var tlsMinVersion, tlsMaxVersion uint16

	// 将 JA4R 中的版本号转换为 uTLS 版本常量
	// JA4R 中的 "13" 表示 TLS 1.3，需要转换为 utls.VersionTLS13
	switch tlsVersion {
	case 13:
		// TLS 1.3
		tlsMinVersion = utls.VersionTLS12
		tlsMaxVersion = utls.VersionTLS13
		if browserType == chrome {
			supportedVersions = append(supportedVersions, utls.GREASE_PLACEHOLDER)
		}
		supportedVersions = append(supportedVersions, utls.VersionTLS13, utls.VersionTLS12)
	case 12:
		// TLS 1.2
		tlsMinVersion = utls.VersionTLS11
		tlsMaxVersion = utls.VersionTLS12
		if browserType == chrome {
			supportedVersions = append(supportedVersions, utls.GREASE_PLACEHOLDER)
		}
		supportedVersions = append(supportedVersions, utls.VersionTLS12, utls.VersionTLS11)
	case 11:
		// TLS 1.1
		tlsMinVersion = utls.VersionTLS10
		tlsMaxVersion = utls.VersionTLS11
		if browserType == chrome {
			supportedVersions = append(supportedVersions, utls.GREASE_PLACEHOLDER)
		}
		supportedVersions = append(supportedVersions, utls.VersionTLS11, utls.VersionTLS10)
	default:
		// 默认使用 TLS 1.2 和 1.3
		tlsMinVersion = utls.VersionTLS12
		tlsMaxVersion = utls.VersionTLS13
		if browserType == chrome {
			supportedVersions = append(supportedVersions, utls.GREASE_PLACEHOLDER)
		}
		supportedVersions = append(supportedVersions, utls.VersionTLS13, utls.VersionTLS12)
	}

	extMap["43"] = &utls.SupportedVersionsExtension{
		Versions: supportedVersions,
	}

	// 设置签名算法扩展（扩展ID 13 = 0x000d）
	var sigAlgorithms []utls.SignatureScheme
	for _, sigID := range signatureAlgorithmsIDs {
		sigAlgorithms = append(sigAlgorithms, utls.SignatureScheme(sigID))
	}
	extMap["13"] = &utls.SignatureAlgorithmsExtension{
		SupportedSignatureAlgorithms: sigAlgorithms,
	}

	// 构建扩展列表（严格按照 JA4R 中的顺序）
	// 按照 extensionIDs 的顺序逐个处理，确保顺序一致
	var extList []utls.TLSExtension
	var pskExt utls.TLSExtension

	// 按照 JA4R 中的扩展顺序逐个处理
	for _, extID := range extensionIDs {
		extKey := fmt.Sprintf("%d", extID)

		// 特殊处理 PSK 扩展，需要放在最后
		if extID == 0x0029 { // pre_shared_key
			// 从 extMap 获取或生成 PSK 扩展
			if ext, ok := extMap[extKey]; ok {
				pskExt = ext
			} else {
				pskExt = generateFakePSKExtension()
			}
			continue // 先跳过，最后再添加
		}

		// 优先从 extMap 中获取已配置的扩展
		if ext, ok := extMap[extKey]; ok {
			extList = append(extList, ext)
		} else {
			// 如果 extMap 中没有，根据扩展ID创建相应的扩展
			var ext utls.TLSExtension
			switch extID {
			case 0x0000: // server_name
				ext = &utls.SNIExtension{}
			case 0x0015: // padding
				ext = &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}
			case 0x0017: // extended_master_secret
				ext = &utls.ExtendedMasterSecretExtension{}
			case 0x0016: // encrypt_then_mac
				ext = &utls.GenericExtension{Id: 0x0016}
			case 0x0023: // session_ticket
				ext = &utls.SessionTicketExtension{}
			case 0x002d: // psk_key_exchange_modes
				ext = &utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}}
			case 0x0033: // key_share
				// KeyShare 扩展需要根据浏览器类型设置
				var keyShares []utls.KeyShare
				if browserType == chrome {
					keyShares = append(keyShares, utls.KeyShare{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}})
				}
				keyShares = append(keyShares, utls.KeyShare{Group: utls.X25519})
				ext = &utls.KeyShareExtension{KeyShares: keyShares}
			default:
				// 对于其他未知扩展，创建通用扩展
				ext = &utls.GenericExtension{Id: extID}
			}
			extList = append(extList, ext)
		}
	}

	// 处理 PSK 扩展：确保它在最后（如果存在）
	if pskExt != nil {
		// Chrome 的最后一个 GREASE 扩展应该在 PSK 之前
		if browserType == chrome {
			extList = append(extList, &utls.UtlsGREASEExtension{Body: []byte{}})
		}
		extList = append(extList, pskExt)
	} else {
		// 如果没有 PSK，Chrome 的 GREASE 在最后
		if browserType == chrome {
			extList = append(extList, &utls.UtlsGREASEExtension{Body: []byte{}})
		}
	}

	// 处理密码套件（Chrome 需要添加 GREASE）
	var finalCipherSuites []uint16
	if browserType == chrome {
		finalCipherSuites = append(finalCipherSuites, utls.GREASE_PLACEHOLDER)
	}
	finalCipherSuites = append(finalCipherSuites, cipherSuiteIDs...)

	// 创建 ClientHelloSpec
	spec := &utls.ClientHelloSpec{
		TLSVersMin:         tlsMinVersion,
		TLSVersMax:         tlsMaxVersion,
		CipherSuites:       finalCipherSuites,
		CompressionMethods: []byte{0x00}, // 无压缩
		Extensions:         extList,
		GetSessionID:       sha256.Sum256,
	}

	return spec, nil
}
