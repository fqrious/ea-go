package ea

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sync/semaphore"
)

var PROXIES []string

func coinFlip() bool {
	return rand.Float32() > 0.5
}

func makePassword(passwd string) string {
	a, _ := regexp.Compile(`[A-Z]`)
	b, _ := regexp.Compile(`[a-z]`)
	c, _ := regexp.Compile(`[0-9]`)
	passes := true
	for _, re := range []*regexp.Regexp{a, b, c} {
		passes = passes && re.Match([]byte(passwd))
	}
	if passes {
		return passwd
	} else {
		return passwd + "#1Ab"
	}
}

func usernameFromEmail(email string) string {
	email = strings.SplitN(email, "@", 2)[0]
	re, _ := regexp.Compile(`\w{4,8}`)
	all := re.FindAllString(email, 3)
	if len(all) < 2 {
		return usernameFromEmail(email + "-" + randomString(8))
	}
	id := all[rand.Intn(len(all))]

	if coinFlip() {
		if coinFlip() {
			id += "_"
		} else {
			id += "-"
		}
	}
	if coinFlip() {
		id += all[rand.Intn(len(all))]
	}

	if coinFlip() {
		id += fmt.Sprint(rand.Intn(120))
	}
	if coinFlip() {
		id += randomString(2)
	}
	if coinFlip() {
		id = strings.ToLower(id)
	}
	slice_end := 16
	if slice_end > len(id) {
		slice_end = len(id)
	}
	return id[:slice_end]
}

func loadAccounts() (sessions []*session) {
	f, err := os.ReadFile("accounts.txt")
	if err != nil {
		panic(err)
	}
	ff := string(f)
	for _, line := range strings.Split(ff, "\n") {
		line = strings.TrimSpace(line)
		splits := strings.Split(line, ",")
		if len(splits) < 2 {
			continue
		}
		email, passwd := splits[0], splits[1]
		sessions = append(sessions, &session{
			Email:       email,
			Password:    makePassword(passwd),
			countryCode: "PL",
			OriginId:    usernameFromEmail(line),
			dobDay:      1 + rand.Intn(27),
			dobMonth:    1 + rand.Intn(11),
			dobYear:     2005 - rand.Intn(20),
			imapHost:    "imap-mail.outlook.com:993",
			imapFolder:  "INBOX",
			imapUser:    email,
			ImapPasswd:  passwd,
		})
	}
	return sessions
}

func loadProxies() (proxies []string) {
	f, err := os.ReadFile("proxies.txt")
	if err != nil {
		panic(err)
	}
	ff := string(f)
	for _, line := range strings.Split(ff, "\n") {
		line = strings.TrimSpace(line)
		splits := strings.SplitN(line, ":", 4)
		if len(splits) < 2 {
			continue
		}
		var user, passwd string
		host, port := splits[0], splits[1]
		if len(splits) >= 4 {
			user = splits[2]
			passwd = splits[3]
		}
		proxies = append(proxies, fmt.Sprintf("http://%s:%s@%s:%s", user, passwd, host, port))
	}
	return proxies
}

func Start() {
	CONCURRENT_TASKS := runtime.GOMAXPROCS(0) * 2
	sem := semaphore.NewWeighted(int64(CONCURRENT_TASKS))
	ctx := context.TODO()
	ALL_ACCOUNTS := loadAccounts()

	LOGS_DIR := "./logs"
	err := os.MkdirAll(LOGS_DIR, 6644)
	if err != nil {
		panic(err)
	}
	startTime := time.Now().Unix()
	f, err := os.OpenFile(fmt.Sprintf("%s/logs-%d.txt", LOGS_DIR, startTime), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	acc_file, err := os.OpenFile(fmt.Sprintf("%s/accounts-%d.txt", LOGS_DIR, startTime), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	acc_file.WriteString("email,email_password,ea_password,status\n")
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("// start of file, running %d concurrent, %d accounts\n", CONCURRENT_TASKS, len(ALL_ACCOUNTS)))
	if err != nil {
		log.Panic("unable to write file:", err)
	}

	for n, acc := range ALL_ACCOUNTS {
		err = sem.Acquire(ctx, 1)
		if err != nil {
			log.Panicln(n, err)
		}
		go func(s *session, n int) {
			s.proxy = PROXIES[rand.Intn(len(PROXIES))]
			defer sem.Release(1)
			t := time.Now().UnixMilli()
			m := map[string]any{
				"session": s,
			}
			out, err := s.doSignup()
			if err != nil {
				acc_file.WriteString(fmt.Sprintf("%s,%s,%s,failed\n", s.Email, s.ImapPasswd, s.Password))
				m["error"] = err.Error()
			} else {
				acc_file.WriteString(fmt.Sprintf("%s,%s,%s,passed\n", s.Email, s.ImapPasswd, s.Password))
			}
			m["out"] = out
			m["time"] = fmt.Sprintf("%.2f seconds", float64(time.Now().UnixMilli()-t)/1000)
			son, _ := json.Marshal(m)
			son = append(son, '\n')
			_, err = f.Write(son)

		}(acc, n)

	}
	if err := sem.Acquire(ctx, int64(CONCURRENT_TASKS)); err != nil {
		log.Printf("Failed to acquire semaphore: %v", err)
	}
	_, err = f.WriteString(fmt.Sprintf("// [%d] end of file\n", time.Now().Unix()))
}

func init() {
	// PROXIES = loadProxies()
	PROXIES = []string{""}
}
