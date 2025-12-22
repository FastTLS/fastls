package fastls

import (
	cryptorand "crypto/rand"
	"fmt"
	"math"
	mathrand "math/rand"
	"strconv"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ============================================================================
// 扩展映射表（用于字符串到类型的转换）
// ============================================================================

var supportedSignatureAlgorithmsExtensions = map[string]utls.SignatureScheme{
	"PKCS1WithSHA256":                     utls.PKCS1WithSHA256,
	"PKCS1WithSHA384":                     utls.PKCS1WithSHA384,
	"PKCS1WithSHA512":                     utls.PKCS1WithSHA512,
	"PSSWithSHA256":                       utls.PSSWithSHA256,
	"PSSWithSHA384":                       utls.PSSWithSHA384,
	"PSSWithSHA512":                       utls.PSSWithSHA512,
	"ECDSAWithP256AndSHA256":              utls.ECDSAWithP256AndSHA256,
	"ECDSAWithP384AndSHA384":              utls.ECDSAWithP384AndSHA384,
	"ECDSAWithP521AndSHA512":              utls.ECDSAWithP521AndSHA512,
	"Ed25519":                             utls.Ed25519,
	"PKCS1WithSHA1":                       utls.PKCS1WithSHA1,
	"ECDSAWithSHA1":                       utls.ECDSAWithSHA1,
	"rsa_pkcs1_sha1":                      utls.SignatureScheme(0x0201),
	"Reserved for backward compatibility": utls.SignatureScheme(0x0202),
	"ecdsa_sha1":                          utls.SignatureScheme(0x0203),
	"rsa_pkcs1_sha256":                    utls.SignatureScheme(0x0401),
	"ecdsa_secp256r1_sha256":              utls.SignatureScheme(0x0403),
	"rsa_pkcs1_sha256_legacy":             utls.SignatureScheme(0x0420),
	"rsa_pkcs1_sha384":                    utls.SignatureScheme(0x0501),
	"ecdsa_secp384r1_sha384":              utls.SignatureScheme(0x0503),
	"rsa_pkcs1_sha384_legacy":             utls.SignatureScheme(0x0520),
	"rsa_pkcs1_sha512":                    utls.SignatureScheme(0x0601),
	"ecdsa_secp521r1_sha512":              utls.SignatureScheme(0x0603),
	"rsa_pkcs1_sha512_legacy":             utls.SignatureScheme(0x0620),
	"eccsi_sha256":                        utls.SignatureScheme(0x0704),
	"iso_ibs1":                            utls.SignatureScheme(0x0705),
	"iso_ibs2":                            utls.SignatureScheme(0x0706),
	"iso_chinese_ibs":                     utls.SignatureScheme(0x0707),
	"sm2sig_sm3":                          utls.SignatureScheme(0x0708),
	"gostr34102012_256a":                  utls.SignatureScheme(0x0709),
	"gostr34102012_256b":                  utls.SignatureScheme(0x070A),
	"gostr34102012_256c":                  utls.SignatureScheme(0x070B),
	"gostr34102012_256d":                  utls.SignatureScheme(0x070C),
	"gostr34102012_512a":                  utls.SignatureScheme(0x070D),
	"gostr34102012_512b":                  utls.SignatureScheme(0x070E),
	"gostr34102012_512c":                  utls.SignatureScheme(0x070F),
	"rsa_pss_rsae_sha256":                 utls.SignatureScheme(0x0804),
	"rsa_pss_rsae_sha384":                 utls.SignatureScheme(0x0805),
	"rsa_pss_rsae_sha512":                 utls.SignatureScheme(0x0806),
	"ed25519":                             utls.SignatureScheme(0x0807),
	"ed448":                               utls.SignatureScheme(0x0808),
	"rsa_pss_pss_sha256":                  utls.SignatureScheme(0x0809),
	"rsa_pss_pss_sha384":                  utls.SignatureScheme(0x080A),
	"rsa_pss_pss_sha512":                  utls.SignatureScheme(0x080B),
	"ecdsa_brainpoolP256r1tls13_sha256":   utls.SignatureScheme(0x081A),
	"ecdsa_brainpoolP384r1tls13_sha384":   utls.SignatureScheme(0x081B),
	"ecdsa_brainpoolP512r1tls13_sha512":   utls.SignatureScheme(0x081C),
}

var certCompressionAlgoExtensions = map[string]utls.CertCompressionAlgo{
	"zlib":   utls.CertCompressionZlib,
	"brotli": utls.CertCompressionBrotli,
	"zstd":   utls.CertCompressionZstd,
}

var supportedVersionsExtensions = map[string]uint16{
	"GREASE": utls.GREASE_PLACEHOLDER,
	"1.3":    utls.VersionTLS13,
	"1.2":    utls.VersionTLS12,
	"1.1":    utls.VersionTLS11,
	"1.0":    utls.VersionTLS10,
}

var pskKeyExchangeModesExtensions = map[string]uint8{
	"PskModeDHE":   utls.PskModeDHE,
	"PskModePlain": utls.PskModePlain,
}

var keyShareCurvesExtensions = map[string]utls.KeyShare{
	"GREASE": utls.KeyShare{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
	"P256":   utls.KeyShare{Group: utls.CurveP256},
	"P384":   utls.KeyShare{Group: utls.CurveP384},
	"P521":   utls.KeyShare{Group: utls.CurveP521},
	"X25519": utls.KeyShare{Group: utls.X25519},
}

// ============================================================================
// 扩展结构体定义
// ============================================================================

// Extensions 用于 JSON 序列化的扩展配置结构体
type Extensions struct {
	SupportedSignatureAlgorithms []string `json:"SupportedSignatureAlgorithms"`
	CertCompressionAlgo          []string `json:"CertCompressionAlgo"`
	RecordSizeLimit              int      `json:"RecordSizeLimit"`
	DelegatedCredentials         []string `json:"DelegatedCredentials"`
	SupportedVersions            []string `json:"SupportedVersions"`
	PSKKeyExchangeModes          []string `json:"PSKKeyExchangeModes"`
	SignatureAlgorithmsCert      []string `json:"SignatureAlgorithmsCert"`
	KeyShareCurves               []string `json:"KeyShareCurves"`
	UseGREASE                    bool     `json:"UseGREASE"`
}

// TLSExtensions 实际的 TLS 扩展对象结构体
type TLSExtensions struct {
	SupportedSignatureAlgorithms *utls.SignatureAlgorithmsExtension
	CertCompressionAlgo          *utls.UtlsCompressCertExtension
	RecordSizeLimit              *utls.FakeRecordSizeLimitExtension
	DelegatedCredentials         *utls.DelegatedCredentialsExtension
	SupportedVersions            *utls.SupportedVersionsExtension
	PSKKeyExchangeModes          *utls.PSKKeyExchangeModesExtension
	SignatureAlgorithmsCert      *utls.SignatureAlgorithmsCertExtension
	KeyShareCurves               *utls.KeyShareExtension
	UseGREASE                    bool
}

// ============================================================================
// 配置转换函数（从 JSON 配置转换为 TLS 扩展对象）
// ============================================================================

// ToTLSExtensions 将 Extensions 配置转换为 TLSExtensions 对象
func ToTLSExtensions(e *Extensions) (extensions *TLSExtensions) {
	extensions = &TLSExtensions{}
	if e == nil {
		return extensions
	}
	if e.SupportedSignatureAlgorithms != nil {
		extensions.SupportedSignatureAlgorithms = &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{}}
		for _, s := range e.SupportedSignatureAlgorithms {
			var signature_algorithms utls.SignatureScheme
			if val, ok := supportedSignatureAlgorithmsExtensions[s]; ok {
				signature_algorithms = val
			} else {
				hexInt, _ := strconv.ParseInt(s, 0, 0)
				signature_algorithms = utls.SignatureScheme(hexInt)
			}
			extensions.SupportedSignatureAlgorithms.SupportedSignatureAlgorithms = append(extensions.SupportedSignatureAlgorithms.SupportedSignatureAlgorithms, signature_algorithms)
		}
	}
	if e.CertCompressionAlgo != nil {
		extensions.CertCompressionAlgo = &utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{}}
		for _, s := range e.CertCompressionAlgo {
			extensions.CertCompressionAlgo.Algorithms = append(extensions.CertCompressionAlgo.Algorithms, certCompressionAlgoExtensions[s])
		}
	}
	if e.RecordSizeLimit != 0 {
		hexStr := fmt.Sprintf("0x%v", e.RecordSizeLimit)
		hexInt, _ := strconv.ParseInt(hexStr, 0, 0)
		extensions.RecordSizeLimit = &utls.FakeRecordSizeLimitExtension{uint16(hexInt)}
	}
	if e.DelegatedCredentials != nil {
		extensions.DelegatedCredentials = &utls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{}}
		for _, s := range e.DelegatedCredentials {
			var signature_algorithms utls.SignatureScheme
			if val, ok := supportedSignatureAlgorithmsExtensions[s]; ok {
				signature_algorithms = val
			} else {
				hexStr := fmt.Sprintf("0x%v", e.RecordSizeLimit)
				hexInt, _ := strconv.ParseInt(hexStr, 0, 0)
				signature_algorithms = utls.SignatureScheme(hexInt)
			}
			extensions.DelegatedCredentials.SupportedSignatureAlgorithms = append(extensions.DelegatedCredentials.SupportedSignatureAlgorithms, signature_algorithms)
		}
	}
	if e.SupportedVersions != nil {
		extensions.SupportedVersions = &utls.SupportedVersionsExtension{Versions: []uint16{}}
		for _, s := range e.SupportedVersions {
			extensions.SupportedVersions.Versions = append(extensions.SupportedVersions.Versions, supportedVersionsExtensions[s])
		}
	}
	if e.PSKKeyExchangeModes != nil {
		extensions.PSKKeyExchangeModes = &utls.PSKKeyExchangeModesExtension{Modes: []uint8{}}
		for _, s := range e.PSKKeyExchangeModes {
			extensions.PSKKeyExchangeModes.Modes = append(extensions.PSKKeyExchangeModes.Modes, pskKeyExchangeModesExtensions[s])
		}
	}
	if e.SignatureAlgorithmsCert != nil {
		extensions.SignatureAlgorithmsCert = &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{}}
		for _, s := range e.SignatureAlgorithmsCert {
			var signature_algorithms_cert utls.SignatureScheme
			if val, ok := supportedSignatureAlgorithmsExtensions[s]; ok {
				signature_algorithms_cert = val
			} else {
				hexStr := fmt.Sprintf("0x%v", e.RecordSizeLimit)
				hexInt, _ := strconv.ParseInt(hexStr, 0, 0)
				signature_algorithms_cert = utls.SignatureScheme(hexInt)
			}
			extensions.SignatureAlgorithmsCert.SupportedSignatureAlgorithms = append(extensions.SignatureAlgorithmsCert.SupportedSignatureAlgorithms, signature_algorithms_cert)
		}
	}
	if e.KeyShareCurves != nil {
		extensions.KeyShareCurves = &utls.KeyShareExtension{KeyShares: []utls.KeyShare{}}
		for _, s := range e.KeyShareCurves {
			extensions.KeyShareCurves.KeyShares = append(extensions.KeyShareCurves.KeyShares, keyShareCurvesExtensions[s])
		}
	}
	if e.UseGREASE {
		extensions.UseGREASE = e.UseGREASE
	}
	return extensions
}

// ============================================================================
// 浏览器类型相关的 TLS 扩展构建函数
// ============================================================================

// buildTLSExtensionMap 根据浏览器类型构建 TLS 扩展映射
// includePSK: 是否包含 PSK 扩展（扩展ID 41）
func buildTLSExtensionMap(browserType string, includePSK bool) map[string]utls.TLSExtension {
	extMap := map[string]utls.TLSExtension{
		"0": &utls.SNIExtension{},
		"5": &utls.StatusRequestExtension{},
		// These are applied later
		// "10": &tls.SupportedCurvesExtension{...}
		// "11": &tls.SupportedPointsExtension{...}
		"13": &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: getSignatureAlgorithms(browserType),
		},
		"16": &utls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		"17": &utls.GenericExtension{Id: 17}, // status_request_v2
		"18": &utls.SCTExtension{},
		"21": &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		"22": &utls.GenericExtension{Id: 22}, // encrypt_then_mac
		"23": &utls.ExtendedMasterSecretExtension{},
		"24": &utls.FakeTokenBindingExtension{},
		"27": &utls.UtlsCompressCertExtension{
			Algorithms: getCertCompressionAlgorithms(browserType),
		},
		"28": &utls.FakeRecordSizeLimitExtension{
			Limit: 0x4001,
		}, //Limit: 0x4001
		"34": &utls.DelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.ECDSAWithSHA1,
			},
		},
		"35": &utls.SessionTicketExtension{},
		"43": getSupportedVersionsExtension(browserType),
		"44": &utls.CookieExtension{},
		"45": &utls.PSKKeyExchangeModesExtension{Modes: []uint8{
			utls.PskModeDHE,
		}},
		"49": &utls.GenericExtension{Id: 49}, // post_handshake_auth
		"50": &utls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, // ecdsa_secp256r1_sha256
				utls.ECDSAWithP384AndSHA384, // ecdsa_secp384r1_sha384
				utls.ECDSAWithP521AndSHA512, // ecdsa_secp521r1_sha512
				utls.PSSWithSHA256,          // rsa_pss_rsae_sha256
				utls.PSSWithSHA384,          // rsa_pss_rsae_sha384
				utls.PSSWithSHA512,          // rsa_pss_rsae_sha512
				utls.PKCS1WithSHA256,        // rsa_pkcs1_sha256
				utls.PKCS1WithSHA384,        // rsa_pkcs1_sha384
				utls.SignatureScheme(0x0806),
				utls.SignatureScheme(0x0601),
			},
		}, // signature_algorithms_cert
		"51": &utls.KeyShareExtension{
			KeyShares: getKeyShares(browserType),
		},
		"57":    &utls.QUICTransportParametersExtension{},
		"13172": &utls.NPNExtension{},
		"17513": &utls.ApplicationSettingsExtension{
			SupportedProtocols: []string{
				"h2",
			},
		},
		"17613": &utls.ApplicationSettingsExtensionNew{
			SupportedProtocols: []string{
				"h2",
			},
		},
		"30032": &utls.GenericExtension{Id: 0x7550, Data: []byte{0}}, //FIXME
		"65281": &utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		},
		"65037": &utls.GREASEEncryptedClientHelloExtension{},
	}

	// 根据参数决定是否添加 PSK 扩展
	// 如果JA3中包含41但没有实际PSK数据，使用FakePreSharedKeyExtension来模拟
	// 为了确保扩展41出现在响应中，我们需要提供最小的有效PSK数据
	// 为了更真实的指纹，我们生成变化的PSK数据（模拟真实浏览器的行为）
	if includePSK {
		pskExt := generateFakePSKExtension()
		extMap["41"] = pskExt
	}

	return extMap
}

// getSignatureAlgorithms 根据浏览器类型返回签名算法列表
func getSignatureAlgorithms(browserType string) []utls.SignatureScheme {
	switch browserType {
	case chrome:
		return []utls.SignatureScheme{
			utls.ECDSAWithP256AndSHA256,
			utls.PSSWithSHA256,
			utls.PKCS1WithSHA256,
			utls.ECDSAWithP384AndSHA384,
			utls.PSSWithSHA384,
			utls.PKCS1WithSHA384,
			utls.PSSWithSHA512,
			utls.PKCS1WithSHA512,
			//utls.PKCS1WithSHA1,
		}
	case firefox:
		return []utls.SignatureScheme{
			utls.ECDSAWithP256AndSHA256,
			utls.ECDSAWithP384AndSHA384,
			utls.ECDSAWithP521AndSHA512,
			utls.PSSWithSHA256,
			utls.PSSWithSHA384,
			utls.PSSWithSHA512,
			utls.PKCS1WithSHA256,
			utls.PKCS1WithSHA384,
			utls.PKCS1WithSHA512,
			utls.ECDSAWithSHA1,
			utls.PKCS1WithSHA1,
			//utls.SignatureScheme(0x0806),
			//utls.SignatureScheme(0x0601),
		}
	default:
		// other 类型：兼容其他浏览器和非浏览器，使用通用的签名算法列表
		return []utls.SignatureScheme{
			utls.ECDSAWithP256AndSHA256,
			utls.PSSWithSHA256,
			utls.PKCS1WithSHA256,
			utls.ECDSAWithP384AndSHA384,
			utls.PSSWithSHA384,
			utls.PKCS1WithSHA384,
			utls.ECDSAWithP521AndSHA512,
			utls.PSSWithSHA512,
			utls.PKCS1WithSHA512,
			utls.ECDSAWithSHA1,
			utls.PKCS1WithSHA1,
		}
	}
}

// getCertCompressionAlgorithms 根据浏览器类型返回证书压缩算法列表
func getCertCompressionAlgorithms(browserType string) []utls.CertCompressionAlgo {
	switch browserType {
	case chrome:
		return []utls.CertCompressionAlgo{
			utls.CertCompressionBrotli,
		}
	case firefox:
		return []utls.CertCompressionAlgo{
			utls.CertCompressionZlib,
			utls.CertCompressionBrotli,
			utls.CertCompressionZstd,
		}
	default:
		return []utls.CertCompressionAlgo{
			utls.CertCompressionBrotli,
		}
	}
}

// getSupportedVersionsExtension 根据浏览器类型返回支持的版本扩展
func getSupportedVersionsExtension(browserType string) *utls.SupportedVersionsExtension {
	versions := []uint16{
		utls.VersionTLS13,
		utls.VersionTLS12,
	}
	// Chrome 需要在版本列表前添加 GREASE
	if browserType == chrome {
		versions = append([]uint16{utls.GREASE_PLACEHOLDER}, versions...)
	}
	return &utls.SupportedVersionsExtension{Versions: versions}
}

// getKeyShares 根据浏览器类型返回密钥共享列表
func getKeyShares(browserType string) []utls.KeyShare {
	switch browserType {
	case chrome:
		return []utls.KeyShare{
			{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: utls.X25519MLKEM768, Data: []byte{0}},
			{Group: utls.X25519, Data: []byte{0}},
		}
	case firefox:
		return []utls.KeyShare{
			{Group: utls.X25519MLKEM768, Data: []byte{0}},
			{Group: utls.X25519, Data: []byte{0}},
			{Group: utls.CurveP256},
		}
	default:
		// other 类型：兼容其他浏览器和非浏览器，使用通用的密钥共享曲线
		return []utls.KeyShare{
			{Group: utls.X25519, Data: []byte{0}},
			{Group: utls.CurveP256},
			{Group: utls.CurveP384},
		}
	}
}

// generateFakePSKExtension 生成一个模拟真实浏览器的PSK扩展
// 每次调用都会生成不同的数据，模拟真实浏览器每次请求都不同的行为
func generateFakePSKExtension() *utls.FakePreSharedKeyExtension {
	// 1. 生成随机的identity（模拟会话票据）
	// 真实浏览器的会话票据通常较长，大约在80-150字节之间
	// 根据分析，真实浏览器的identity长度通常在100-120字节左右
	identityLen := 80 + int(time.Now().UnixNano()%71) // 80-150字节之间随机，更接近真实浏览器
	identity := make([]byte, identityLen)
	cryptorand.Read(identity)

	// 2. 计算ObfuscatedTicketAge（混淆的票据年龄）
	// 真实浏览器中，这个值基于会话创建时间和当前时间的差值
	// 我们模拟一个合理的ticket age（通常在几秒到几小时之间）
	// 使用一个随机的基础时间（模拟会话创建时间）
	baseTime := time.Now().Add(-time.Duration(mathrand.Intn(3600)) * time.Second) // 0-1小时前
	ticketAge := time.Since(baseTime)
	obfuscatedTicketAge := uint32(ticketAge.Milliseconds())
	// 添加一个随机的ageAdd值（服务器在NewSessionTicket中发送的）
	ageAdd := uint32(mathrand.Int31()) // 生成0到2^31-1的随机数，然后转换为uint32
	obfuscatedTicketAge = (obfuscatedTicketAge + ageAdd) & math.MaxUint32

	// 3. 生成随机的binder（32字节，SHA256 HMAC长度）
	// 真实浏览器中，binder是基于ClientHello消息计算的HMAC
	// 我们使用随机数据来模拟
	binder := make([]byte, 32)
	cryptorand.Read(binder)

	return &utls.FakePreSharedKeyExtension{
		Identities: []utls.PskIdentity{
			{
				Label:               identity,
				ObfuscatedTicketAge: obfuscatedTicketAge,
			},
		},
		Binders: [][]byte{
			binder,
		},
		OmitEmptyPsk: false, // 设置为false，确保扩展会被写入
	}
}
