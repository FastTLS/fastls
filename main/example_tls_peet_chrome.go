package main

import (
	"io"
	"log"

	fastls "github.com/ChengHoward/Fastls"
	"github.com/ChengHoward/Fastls/imitate"
)

func main() {

	client := fastls.NewClient()

	options := fastls.Options{
		Timeout: 60,
		Headers: map[string]string{
			"sec-fetch-site":  "same-site",
			"sec-fetch-mode":  "cors",
			"sec-fetch-user":  "?1",
			"sec-fetch-dest":  "empty",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,sq;q=0.7",
			"Referer":         "https://link.2505.top/article/10.1007/s10029-020-02328-x",
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Electron/25.2.0 Safari/537.36",
		},
		Proxy:   "socks5://127.0.0.1:10808",
		Cookies: []fastls.Cookie{},
	}

	imitate.Chrome(&options)
	//imitate.Firefox(&options)
	//imitate.Chromium(&options)
	//imitate.Edge(&options)
	//imitate.Chrome(&options)

	//options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Electron/25.2.0 Safari/537.36"

	resp, err := client.Do("https://tls.peet.ws/api/all", options, "GET")
	if err != nil {
		log.Print("Request Failed: " + err.Error())
		return
	}
	body, err := io.ReadAll(resp.Body)

	log.Print(resp.Status)
	log.Print(string(body))

}
