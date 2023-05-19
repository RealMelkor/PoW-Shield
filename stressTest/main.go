package main

import (
	"log"
	"strconv"
	"errors"
	"net/http"
	"encoding/base64"
	"encoding/binary"
	"crypto/sha256"
	"io/ioutil"
	"time"
	"runtime"
	"os"
	"fmt"
)

func resolve(url, id, answer string) ([]byte, error) {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.AddCookie(&http.Cookie{Name: "pow-shield-id", Value: id})
	req.AddCookie(&http.Cookie{Name: "pow-shield-answer", Value: answer})

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = errors.New("status: " + strconv.Itoa(resp.StatusCode))
		return nil, err
	}

	return ioutil.ReadAll(resp.Body)
}

func request(url string, work uint32) {

	rawData := make([]byte, 36)
	resp, err := http.Get(url)
	if err != nil {

		log.Fatal(err)
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if (len(cookies) < 2) {
		log.Fatalln("invalid response");
		return
	}
	id := resp.Cookies()[0].Value
	challenge := resp.Cookies()[1].Value
	resp.Body.Close()
	
        data, err := base64.StdEncoding.DecodeString(challenge)
        if err != nil {
                log.Fatal("invalid base64:", err)
        }
	if len(data) != 32 {
                log.Fatal("invalid data length", len(data))
	}
	
	copy(rawData, data)
	var answer string
	for i := uint32(0); i < 0xFFFFFFFF; i++ {
		binary.LittleEndian.PutUint32(rawData[32:], i)
		hash := sha256.Sum256(rawData[0:36])
		start := binary.LittleEndian.Uint32(hash[0:4])
		if start <= work {
			answer = strconv.FormatUint(uint64(i), 10)
			break;
		}
		i++
	}

	for i := 0; i < 100; i++ {
		data, err = resolve(url, id, answer)
		if err != nil {
			break
		}
	}
}

var count = 0

func requestRoutine(url string, work uint32) {
	for i := 0; ; i++ {
		request(url, work)
		count++
	}
}

func main() {
	work := uint32(0x00005FFF)
	if len(os.Args) < 2 {
		fmt.Println(os.Args[0] + " <url> [work]")
		return
	}
	if len(os.Args) > 2 {
		i, err := strconv.ParseUint(os.Args[2], 16, 32)
		if err != nil {
			fmt.Println("Invalid work value")
			return
		}
		work = uint32(i)
	}
	start := time.Now().UnixMilli()
	for i := 0; i < runtime.NumCPU(); i++ {
		go requestRoutine(os.Args[1], work)
	}
	for {
		time.Sleep(time.Second)
		log.Println(int64(count) * 1000 /
			(time.Now().UnixMilli() - start + 1),
			"total request/second")
	}
}
