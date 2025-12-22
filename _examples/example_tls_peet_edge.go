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
		//resp, err := client.Do("https://tls.peet.ws/api/all", fastls.Options{
		//Ja3:           chrome109Ja3(),
		//Ja3:           "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
		//Ja3: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		//HTTP2Settings: h2ss,
		//UserAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
		//Proxy:     "socks5://abc:321@127.0.0.1:1087",
		Headers: map[string]string{
			"Accept":          "Application/json, text/plain, */*",
			"Accept-Language": "en-US,en;q=0.5",
		},
	}

	//imitate.Chrome(&options)
	//imitate.Firefox(&options)
	//imitate.Chromium(&options)
	imitate.Edge(&options)
	//imitate.Safari(&options)

	resp, err := client.Do("https://tls.peet.ws/api/all", options, "GET")
	//resp, err := client.Do("https://tls.browserleaks.com/json", options, "GET")
	if err != nil {
		log.Print("Request Failed: " + err.Error())
		return
	}
	body, err := io.ReadAll(resp.Body)

	log.Print(resp.Status)
	log.Print(string(body))

}
