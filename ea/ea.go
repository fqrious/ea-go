package ea

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"regexp"
	"slices"
	"strings"
	"time"

	orderedform "github.com/CrimsonAIO/ordered-form"
	"github.com/PuerkitoBio/goquery"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	capsolver_go "github.com/capsolver/capsolver-go"
	"github.com/pquerna/otp/totp"
)

var (
	MAX_REDIRECTS            = 5
	PROFILE_VISIBILITY_TYPES = []string{
		"EVERYONE", "FRIENDS", "FRIENDS_OF_FRIENDS", "NO_ONE",
	}
	CAPSOLVER_API_KEY               = "CAP-FF80A732E8DD74A028F60E4820776966"
	EMAIL_WAIT_TIME   time.Duration = 30 // 30 seconds
	TLS_PROFILES                    = []profiles.ClientProfile{
		profiles.Chrome_120,
		profiles.Chrome_117,
		profiles.Firefox_120,
		profiles.Firefox_117,
		profiles.Safari_Ipad_15_6,
		profiles.Safari_IOS_16_0,
		profiles.Safari_15_6_1,
	}
)

func (s *session) createClient(proxy string) tls_client.HttpClient {
	tls_client_profile := TLS_PROFILES[rand.Intn(len(TLS_PROFILES))]
	s.TLSProfile = tls_client_profile.GetClientHelloStr()

	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithInsecureSkipVerify(),
		// tls_client.WithCustomRedirectFunc(func(req *fhttp.Request, via []*fhttp.Request) error {
		// 	req.Host = strings.Replace(req.Host, ":443", "", 1)
		// 	if req.URL.Port() == "443" || req.URL.Port() == "80" {
		// 		req.URL.Host = req.URL.Hostname()
		// 		req.Host = req.URL.Host
		// 	}
		// 	req.Header.Del("Referer")
		// 	if len(via) >= MAX_REDIRECTS {
		// 		return fmt.Errorf("stopped after %d redirects", MAX_REDIRECTS)
		// 	}
		// 	return nil
		// }),
		tls_client.WithClientProfile(tls_client_profile),
		// tls_client.WithClientProfile(BraveIOS),
		tls_client.WithProxyUrl(proxy),
		// tls_client.WithForceHttp1(),
		tls_client.WithCookieJar(jar),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		panic(err)
	}
	s.client = client

	return client
}

type session struct {
	client                    tls_client.HttpClient
	Email                     string `json:"email,omitempty"`
	Password                  string `json:"password,omitempty"`
	OriginId                  string `json:"origin_id,omitempty"`
	countryCode               string
	imapHost                  string
	imapUser                  string
	ImapPasswd                string
	imapFolder                string
	dobDay, dobMonth, dobYear int
	imapSession               *ImapSession
	TwoFactorSecret           string `json:"2fa_secret,omitempty"`
	proxy                     string
	TLSProfile                string
}

func (s *session) generate2facode() string {
	otp, _ := totp.GenerateCode(s.TwoFactorSecret, time.Now())
	return otp
}

func (s *session) getEACode(loopTime time.Time) (string, error) {
	startTime := time.Now()
	emailClient, err := s.newImapSession()
	if err != nil {
		return "", err
	}
	log.Printf("wait %d seconds for email to arrive\n", int(EMAIL_WAIT_TIME))
	time.Sleep(EMAIL_WAIT_TIME * time.Second) // sleep 1 minute to make sure the code enters before proceeding
	messages, err := emailClient.readInbox(s.imapFolder, loopTime.Add(-1*time.Minute))
	if err != nil {
		return "", err
	}
	code := GetEACode(messages)
	if code == "" {
		return "", fmt.Errorf("couldn't find verification code after %d seconds", int(time.Now().Sub(startTime).Seconds()))
	}
	return code, nil
}

var SKIP_KEYS = []string{
	"host",
	"cookie",
	"content-length",
}

func shouldSkip(header string) bool {
	if header[0] == ':' {
		return true
	}
	header = strings.ToLower(header)
	for _, skip := range SKIP_KEYS {
		if skip == header {
			return true
		}
	}
	return false
}

func randomString(length int) (out string) {
	letters := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz"
	for i := 0; i < length; i++ {
		out += string(letters[rand.Intn(len(letters))])
	}
	return out
}

func (s *session) makeRequest(req *fhttp.Request, headers [][2]string, referer string) (resp *fhttp.Response, err error) {
	if s.client == nil {
		s.client = s.createClient(s.proxy)
	}
	// req.Header.Add(fhttp.HeaderOrderKey, "Host")
	for _, vv := range headers {
		k, v := vv[0], vv[1]
		if !shouldSkip(k) {
			req.Header.Add(k, v)
		}

		req.Header.Add(fhttp.HeaderOrderKey, k)
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	for i := 0; i < 5; i++ {
		resp, err = s.client.Do(req)
		if err == nil {
			break
		} else {
			s.proxy = PROXIES[rand.Intn(len(PROXIES))] // swap proxy
			log.Println("changed proxy to", s.proxy)
		}
	}
	return

}

func solveFuncaptcha(client *session, email, referer string) (string, error) {
	CATEGORY_PUBLICKEY_MAP := map[string]string{
		"juno/create": "73BEC076-3E53-30F5-B1EB-84F494D43DBA",
		"juno/login":  "0F5FE186-B3CA-4EDB-A39B-9B9A3397D01D",
	}
	if referer == "" {
		return "", fmt.Errorf("cannot solve funcaptcha without juno referer")
	}
	re, _ := regexp.Compile(`juno/\w+`)
	category := re.FindString(referer)
	publicKey, ok := CATEGORY_PUBLICKEY_MAP[category]
	if !ok {
		return "", fmt.Errorf("unrecognized juno path for funcaptcha: `%s`", category)
	}
	curl := "https://signin.ea.com/p/ajax/funcaptcha/encrypt"
	headers := [][2]string{
		{"Host", "signin.ea.com"},
		{"Connection", "keep-alive"},
		{"Content-Length", "55"},
		{"sec-ch-ua", "\"Brave\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\""},
		{"Accept", "application/json, text/javascript, */*; q=0.01"},
		{"Content-Type", "application/json;charset=UTF-8"},
		{"X-Requested-With", "XMLHttpRequest"},
		{"sec-ch-ua-mobile", "?0"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"},
		{"sec-ch-ua-platform", "\"Linux\""},
		{"Sec-GPC", "1"},
		{"Accept-Language", "en-US,en;q=0.8"},
		{"Origin", "https://signin.ea.com"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Dest", "empty"},
		{"Referer", referer},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Cookie", ""},
	}
	body_bytes, _ := json.Marshal(map[string]string{
		"email_domain": strings.Split(email, "@")[1],
		"timestamp":    fmt.Sprint(time.Now().UnixMilli()),
	})
	req, _ := fhttp.NewRequest("POST", curl, bytes.NewBuffer(body_bytes))
	resp, err := client.makeRequest(req, headers, "")
	if err != nil {
		return "", err
	}
	resp_map := map[string]string{}
	resp_byte, err := io.ReadAll(resp.Body)
	err = json.Unmarshal(resp_byte, &resp_map)
	if err != nil {
		return "", err
	}
	blob := resp_map["encryptData"]
	if blob == "" {
		return "", fmt.Errorf("solve captcha failed: no encryptData in captcha response, got: %s", resp_byte)
	}
	capSolver := capsolver_go.CapSolver{
		ApiKey: CAPSOLVER_API_KEY,
	}
	solution, err := capSolver.Solve(map[string]any{
		"type":             "FunCaptchaTaskProxyLess",
		"websitePublicKey": publicKey,
		"websiteURL":       referer,
		// "proxy":            "ip:port:username:password",
		"data": "{\"blob\": \"" + blob + "\"}",
	})
	if err != nil {
		// return "", fmt.Errorf("capsolver task failed: %s (%d)", solution.ErrorDescription, solution.ErrorId)
		return "", fmt.Errorf("solve captcha failed: %v", err)
	}
	return solution.Solution.Token, nil
}

func verifyEmail(client *session, postUrl, code string) (resp *fhttp.Response, err error) {
	req, _ := fhttp.NewRequest("POST", postUrl, bytes.NewBufferString(fmt.Sprintf("emailVerifyCode=%s&_eventId=submit", code)))
	headers := [][2]string{
		{"Host", ""},
		{"Connection", "keep-alive"},
		{"Content-Length", "100"},
		{"Cache-Control", "max-age=0"},
		{"sec-ch-ua", "\"Brave\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\""},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", "\"Linux\""},
		{"Upgrade-Insecure-Requests", "1"},
		{"Origin", "https://signin.ea.com"},
		{"Content-Type", "application/x-www-form-urlencoded"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
		{"Sec-GPC", "1"},
		{"Accept-Language", "en-US,en;q=0.8"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-User", "?1"},
		{"Sec-Fetch-Dest", "document"},
		{"Referer", postUrl},
	}
	resp, err = client.makeRequest(req, headers, postUrl)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

type AjaxResp struct {
	Status    bool   `json:"status,omitempty"`
	Message   string `json:"message,omitempty"`
	ErrorCode any    `json:"errorCode,omitempty"`
	Underage  bool   `json:"underage,omitempty"`
}

func (s *session) checkEmailExists() bool {
	curl := fmt.Sprintf("https://signin.ea.com/p/ajax/user/checkEmailExisted?requestorId=portal&email=%s&_=%d", s.Email, time.Now().UnixMilli())
	req, _ := fhttp.NewRequest("GET", curl, nil)
	headers := [][2]string{
		{"Accept", "application/json, text/javascript, */*; q=0.01"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Cache-Control", "no-cache"},
		{"Connection", "keep-alive"},
		{"Host", "accounts.ea.com"},
		{"Pragma", "no-cache"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"},
		{"sec-ch-ua", "\"Chromium\";v=\"121\", \"Not A(Brand\";v=\"99\""},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", "\"Linux\""},
	}
	resp, err := s.makeRequest(req, headers, "")
	if err != nil {
		return false
	}
	r, err := parseResp(resp)
	if err != nil {
		return false
	}
	son := AjaxResp{}
	json.Unmarshal(r.body, &son)
	return son.Message == "register_email_existed"
}

func (s *session) checkOriginId() *AjaxResp {
	curl := fmt.Sprintf("https://signin.ea.com/p/ajax/user/checkOriginId?requestorId=portal&originId=%s&_=%d", s.OriginId, time.Now().UnixMilli())
	req, _ := fhttp.NewRequest("GET", curl, nil)
	headers := [][2]string{
		{"Accept", "application/json, text/javascript, */*; q=0.01"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Cache-Control", "no-cache"},
		{"Connection", "keep-alive"},
		{"Host", "accounts.ea.com"},
		{"Pragma", "no-cache"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"},
		{"sec-ch-ua", "\"Chromium\";v=\"121\", \"Not A(Brand\";v=\"99\""},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", "\"Linux\""},
	}
	resp, err := s.makeRequest(req, headers, "")
	if err != nil {
		return nil
	}
	r, err := parseResp(resp)
	if err != nil {
		return nil
	}
	son := &AjaxResp{}
	json.Unmarshal(r.body, son)

	return son
}

func (s *session) doLogin(parsedResp *parsedResponse) (any, error) {
	log.Printf("logging in to: %s ...\n", s.Email)

	url := "https://www.ea.com/login"
	if parsedResp != nil {
		url = parsedResp.resp.Request.URL.String()
	}
	// parsedResp.curStep, parsedResp.prevStep = "juno/loginMainEntry", parsedResp.curStep
	req, _ := fhttp.NewRequest("POST", url, bytes.NewBufferString("_eventId=cancel"))
	headers := [][2]string{
		{"Host", ""},
		{"Connection", "keep-alive"},
		{"Content-Length", "100"},
		{"Cache-Control", "max-age=0"},
		{"sec-ch-ua", "\"Brave\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\""},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", "\"Linux\""},
		{"Upgrade-Insecure-Requests", "1"},
		{"Origin", "https://signin.ea.com"},
		{"Content-Type", "application/x-www-form-urlencoded"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
		{"Sec-GPC", "1"},
		{"Accept-Language", "en-US,en;q=0.8"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-User", "?1"},
		{"Sec-Fetch-Dest", "document"},
		{"Referer", url},
	}
	resp, err := s.makeRequest(req, headers, url)
	if err != nil {
		return nil, err
	}
	parsedResp, err = parseResp(resp)
	if err != nil {
		return nil, err
	}
	return s.junoLoop(parsedResp)
}

func (s *session) findOriginId() (err error) {
	ORIGIN_ID_RETRIES := 5
	if s.OriginId == "" {
		s.OriginId = usernameFromEmail(s.Email)
	}
	tried_ids := []string{s.OriginId}

	for i := 0; i < ORIGIN_ID_RETRIES; i++ {
		log.Printf("[%d/%d] trying origin id: %s", i+1, ORIGIN_ID_RETRIES, s.OriginId)

		originIdResp := s.checkOriginId()
		if !originIdResp.Status {
			err = fmt.Errorf("[%d/%d] origin id `%s` error: %s", i+1, ORIGIN_ID_RETRIES, s.OriginId, originIdResp.Message)
			log.Println(err)
			for {
				s.OriginId = usernameFromEmail(s.Email)
				if !slices.Contains(tried_ids, s.OriginId) {
					break
				}
			}

		} else {
			err = nil
			break
		}
	}
	return
}

func (s *session) junoLoop(parsedResp *parsedResponse) (any, error) {
	resp := parsedResp.resp
	var req *fhttp.Request
	var err error
	loopTime := time.Now()
	headers := [][2]string{
		{"Host", ""},
		{"Connection", "keep-alive"},
		{"Content-Length", "100"},
		{"Cache-Control", "max-age=0"},
		{"sec-ch-ua", "\"Brave\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\""},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", "\"Linux\""},
		{"Upgrade-Insecure-Requests", "1"},
		{"Origin", "https://signin.ea.com"},
		{"Content-Type", "application/x-www-form-urlencoded"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
		{"Sec-GPC", "1"},
		{"Accept-Language", "en-US,en;q=0.8"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-User", "?1"},
		{"Sec-Fetch-Dest", "document"},
		{"Referer", resp.Request.URL.String()},
	}

	cid := randomString(32)
	prevStep := ""
	mode2fa := "EMAIL"

	for stepId := 1; ; stepId++ {
		form := orderedform.Form{}
		log.Printf("JunoLoop STEP-%d: curStep=%s, prevStep=%s\n", stepId, parsedResp.curStep, parsedResp.prevStep)
		if prevStep == parsedResp.curStep {
			return nil, fmt.Errorf("registration step revisited: %s", parsedResp.curStep)
		}
		switch parsedResp.curStep {
		case "juno/dobCountry":
			req, _ = fhttp.NewRequest("POST", resp.Request.URL.String(), bytes.NewBuffer([]byte(fmt.Sprintf("cid=&underage=false&_eventId=submit&country=%s&dobDay=%d&dobMonth=%d&dobYear=%d&koreaVerifyType=iPin", s.countryCode, s.dobDay, s.dobMonth, s.dobYear))))
			resp, err = s.makeRequest(req, headers, "")
		case "juno/basicInfo":
			if err = s.findOriginId(); err != nil {
				return nil, err
			}

			token, err := solveFuncaptcha(s, s.Email, resp.Request.URL.String())
			if err != nil {
				return nil, err
			}
			form.Add("_eventId", "submit")
			form.Add("_readAccept", "on")
			form.Add("_readAcceptUnderage", "on")
			form.Add("cid", "")
			form.Add("email", s.Email)
			form.Add("originId", s.OriginId)
			form.Add("parentEmail", "")
			form.Add("password", s.Password)
			form.Add("thirdPartyCaptchaResponse", token)
			req, _ = fhttp.NewRequest("POST", resp.Request.URL.String(), bytes.NewBufferString(form.Encode(orderedform.PlaintextEncoder)))
			resp, err = s.makeRequest(req, headers, resp.Request.URL.String())
		case "juno/privacySetting":
			form.Add("friendVisibility", PROFILE_VISIBILITY_TYPES[rand.Intn(len(PROFILE_VISIBILITY_TYPES))])
			form.Add("_emailVisibility", "on")
			// form.Add("emailVisibility", "on")
			form.Add("_contactMe", "on")
			form.Add("_readAccept", "on")
			form.Add("readAccept", "on")
			form.Add("cid", cid)
			form.Add("_eventId", "submit")
			req, _ = fhttp.NewRequest("POST", resp.Request.URL.String(), bytes.NewBufferString(form.Encode(orderedform.PlaintextEncoder)))
			resp, err = s.makeRequest(req, headers, resp.Request.URL.String())
		case "juno/upgrade":
			if err = s.findOriginId(); err != nil {
				return nil, err
			}
			form.Add("originId", s.OriginId)
			form.Add("_eventId", "submit")
			req, _ = fhttp.NewRequest("POST", resp.Request.URL.String(), bytes.NewBufferString(form.Encode(orderedform.PlaintextEncoder)))
			resp, err = s.makeRequest(req, headers, resp.Request.URL.String())

		case "juno/loginMainEntry":
			form.Add("email", s.Email)
			form.Add("regionCode", s.countryCode)
			form.Add("phoneNumber", "")
			form.Add("password", s.Password)
			form.Add("_eventId", "submit")
			form.Add("cid", cid)
			form.Add("showAgeUp", "true")
			form.Add("thirdPartyCaptchaResponse", "")
			form.Add("loginMethod", "emailPassword")
			form.Add("_rememberMe", "on")
			form.Add("rememberMe", "on")

			req, _ = fhttp.NewRequest("POST", resp.Request.URL.String(), bytes.NewBufferString(form.Encode(orderedform.PlaintextEncoder)))
			resp, err = s.makeRequest(req, headers, resp.Request.URL.String())
		case "dynamicchallenge/verifyCode":
			log.Println("loop time:", loopTime)
			var code string
			if mode2fa == "EMAIL" {
				code, err = s.getEACode(loopTime)
				if err != nil {
					return nil, err
				}
			} else {
				code = s.generate2facode()
			}
			log.Printf(">> got code '%s' from %s", code, mode2fa)
			form.Add("oneTimeCode", code)
			form.Add("_trustThisDevice", "on")
			form.Add("trustThisDevice", "on")
			form.Add("_eventId", "submit")
			req, _ = fhttp.NewRequest("POST", resp.Request.URL.String(), bytes.NewBufferString(form.Encode(orderedform.PlaintextEncoder)))
			resp, err = s.makeRequest(req, headers, resp.Request.URL.String())
		case "dynamicchallenge/sendCode":
			if s.TwoFactorSecret != "" {
				mode2fa = "APP"
			}
			form.Add("codeType", mode2fa)
			log.Printf("using mode: %s", mode2fa)
			form.Add("maskedDestination", s.Email)
			form.Add("_eventId", "submit")
			req, _ = fhttp.NewRequest("POST", resp.Request.URL.String(), bytes.NewBufferString(form.Encode(orderedform.PlaintextEncoder)))
			resp, err = s.makeRequest(req, headers, resp.Request.URL.String())
		case "juno/mandatoryEmailVerification_verify":
			code, err := s.getEACode(loopTime)
			if err != nil {
				return nil, err
			}
			req, _ = fhttp.NewRequest("POST", resp.Request.URL.String(), bytes.NewBufferString(fmt.Sprintf("emailVerifyCode=%s&_eventId=submit", code)))
			resp, err = s.makeRequest(req, headers, resp.Request.URL.String())
		case "dynamicchallenge/mfaSetup":
			form.Add("_eventId", "submit")
			req, _ = fhttp.NewRequest("POST", resp.Request.URL.String(), bytes.NewBufferString(form.Encode(orderedform.PlaintextEncoder)))
			resp, err = s.makeRequest(req, headers, resp.Request.URL.String())
		case "", "juno/mandatoryEmailVerification_done":
			log.Println("loop done, exiting...")
			return parsedResp, nil
		default:
			return nil, fmt.Errorf("unknown reg step: %s", parsedResp.curStep)
		}
		prevStep = parsedResp.curStep
		// handle errors
		if err != nil {
			return nil, err
		}
		parsedResp, err = parseResp(resp)
		if err != nil {
			return nil, err
		}
	}
}

func (s *session) doSignup() (any, error) {
	log.Printf("signing up with: %s ...\n", s.Email)
	signupUrl := "https://accounts.ea.com/connect/auth?display=web2%2Fcreate&response_type=code&theme=eahelp&redirect_uri=https%3A%2F%2Fhelp.ea.com%2Fsso%2Flogin%2F&locale=en_US&nonce=nonce&client_id=origin_CE"

	req, _ := fhttp.NewRequest("GET", signupUrl, nil)
	headers := [][2]string{
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Cache-Control", "no-cache"},
		{"Connection", "keep-alive"},
		{"Host", "accounts.ea.com"},
		{"Pragma", "no-cache"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"},
		{"sec-ch-ua", "\"Chromium\";v=\"121\", \"Not A(Brand\";v=\"99\""},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", "\"Linux\""},
	}
	resp, err := s.makeRequest(req, headers, "")
	if err != nil {
		return nil, err
	}
	parsedResp, err := parseResp(resp)
	if err != nil {
		return nil, err
	}
	if s.checkEmailExists() {
		//try to login if email exists
		return s.doLogin(parsedResp)
	}

	return s.junoLoop(parsedResp)
}

type parsedResponse struct {
	prevStep string
	curStep  string
	body     []byte
	resp     *fhttp.Response
	document *goquery.Document
}

func parseResp(resp *fhttp.Response) (r *parsedResponse, out error) {
	r = &parsedResponse{
		resp: resp,
	}
	ERROR_SELECTORS := []string{
		"#online-general-error",
		".general-error",
		".otkform-group-haserror",
		".int-registration-error",
		"#panel-underage-limit>.otkc",
	}
	if resp == nil {
		return r, fmt.Errorf("got nil body")
	}
	r.body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode > 299 {
		return r, fmt.Errorf("http request failed with status: %s", resp.Status)
	}

	if !strings.Contains(resp.Header.Get("content-type"), "text/html") {
		return r, nil
	}

	stepRE, _ := regexp.Compile(`(\w+Step)\s*=\s*['"](.+)['"]`)
	for _, matches := range stepRE.FindAllSubmatch(r.body, 100) {
		m1, m2 := string(matches[1]), string(matches[2])
		switch m1 {
		case "curStep":
			r.curStep = m2
		case "prevStep":
			r.prevStep = m2
		}
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(r.body))
	if err != nil {
		return nil, fmt.Errorf("html parse error: %v", err)
	}
	regViews := doc.Find("div.views")
	r.document = doc

	if regViews != nil {

		for _, selector := range ERROR_SELECTORS {
			s := regViews.Find(selector)
			if s != nil {
				if msg := strings.TrimSpace(s.Text()); msg != "" {
					return nil, fmt.Errorf("html error: %s (%s)", msg, selector)
				}
			}
		}
	}
	return
}
