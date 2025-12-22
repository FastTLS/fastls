package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

var safariH2Settings = &fastls.H2Settings{
	Settings: map[string]int{
		"INITIAL_WINDOW_SIZE":    4194304,
		"MAX_CONCURRENT_STREAMS": 100,
	},
	SettingsOrder: []string{
		"INITIAL_WINDOW_SIZE",
		"MAX_CONCURRENT_STREAMS",
	},
	ConnectionFlow: 10485760,
	HeaderPriority: map[string]interface{}{
		"weight":    255,
		"streamDep": 0,
		"exclusive": false,
	},
	PriorityFrames: []map[string]interface{}{
		{
			"streamID": 0,
			"priorityParam": map[string]interface{}{
				"weight":    0,
				"streamDep": 0,
				"exclusive": true,
			},
		},
	},
}
var SafariHttp2Setting = fastls.ToHTTP2Settings(safariH2Settings)

func Safari(options *fastls.Options) {
	options.Fingerprint = fastls.Ja3Fingerprint{
		FingerprintValue: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
	}
	options.HTTP2Settings = SafariHttp2Setting
	options.PHeaderOrderKeys = []string{
		":method",
		":scheme",
		":path",
		":authority",
	}

	if options.Headers["Accept"] == "" {
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	}
	options.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"
}
