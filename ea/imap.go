package ea

import (
	"fmt"
	"log"
	"mime"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/charset"
)

type ImapSession struct {
	*imapclient.Client
}

func (s *session) newImapSession() (*ImapSession, error) {
	if s.imapSession != nil {
		return s.imapSession, nil
	}
	if s.imapUser == "" {
		s.imapUser = s.Email
	}
	if s.ImapPasswd == "" {
		s.ImapPasswd = s.Password
	}

	options := &imapclient.Options{
		WordDecoder: &mime.WordDecoder{CharsetReader: charset.Reader},
	}
	c, err := imapclient.DialTLS(s.imapHost, options)
	if err != nil {
		return nil, err
	}
	err = c.Login(s.imapUser, s.ImapPasswd).Wait()
	if err != nil {
		return nil, err
	}

	s.imapSession = &ImapSession{c}
	return s.imapSession, nil
}

type Message struct {
	From, To imap.Address
	Subject  string
	Folder   string
	Date     time.Time
	Content  string
	Header   string
	Mime     string
}

func (client *ImapSession) readInbox(folder string, since time.Time) ([]Message, error) {
	_, err := client.Select(folder, nil).Wait()
	if err != nil {
		return nil, err
	}
	search_result, err := client.Search(&imap.SearchCriteria{
		Since: since,
	}, nil).Wait()
	if err != nil {
		return nil, err
	}
	if len(search_result.AllSeqNums()) == 0 {
		return nil, fmt.Errorf("search result must have length > 0")
	}
	fetched, err := client.Fetch(search_result.All, &imap.FetchOptions{
		Envelope: true,
		BodySection: []*imap.FetchItemBodySection{
			{
				Specifier: imap.PartSpecifierText,
			},
		},
	}).Collect()
	if err != nil {
		return nil, err
	}
	messages := []Message{}

	for _, msg := range fetched {
		var from imap.Address
		if msg.Envelope.Sender != nil {
			from = msg.Envelope.Sender[0]
		} else {
			from = msg.Envelope.From[0]
		}
		email_msg := Message{
			From:    from,
			Folder:  folder,
			Date:    msg.Envelope.Date,
			Subject: msg.Envelope.Subject,
		}
		log.Printf("Folder: [%s]", folder)
		log.Printf("Subject: %v", msg.Envelope.Subject)
		log.Printf("Sender: %v", email_msg.From.Addr())
		log.Printf("Date: %v", msg.Envelope.Date.String())
		for k, v := range msg.BodySection {
			vstr := string(v)
			log.Printf("Body[%s] length: %d", k.Specifier, len(v))
			switch k.Specifier {
			case imap.PartSpecifierText:
				email_msg.Content = vstr
			case imap.PartSpecifierHeader:
				email_msg.Header = vstr
			case imap.PartSpecifierMIME:
				email_msg.Mime = vstr
			}
		}
		// out, err := json.Marshal(email_msg)
		// log.Println(string(out), err)
		if email_msg.Date.After(since) {
			messages = append(messages, email_msg)
		}
	}
	return messages, nil
}

func (client *ImapSession) readAll(since time.Time) (retval []Message, err error) {
	folders := []string{
		"Junk",
		"INBOX",
	}
	listData, err := client.List(`""`, "*", nil).Collect()
	if err != nil {
		return
	}
	for _, v := range listData {
		log.Printf("found folder: %v", v)
	}
	for _, folder := range folders {
		messages, err := client.readInbox(folder, since)
		if err != nil {
			return nil, err

		}
		log.Println(folder, "length:", len(messages))
		retval = append(retval, messages...)
	}
	return
}

func GetEACode(emails []Message) (code string) {
	HOSTS := []string{"e.ea.com"}
	var date int64 = 0
	for _, email := range emails {
		if slices.Contains(HOSTS, email.From.Host) && email.Date.UnixMilli() > date {
			if splits := strings.Split(email.Subject, ": "); len(splits) > 1 {
				c := splits[len(splits)-1]
				if len(c) == 6 {
					code = c
				}
			}
			if splits := strings.Split(email.Subject, "- "); len(splits) > 1 {
				c := splits[len(splits)-1]
				if len(c) == 6 {
					code = c
				}
			}
		}
	}
	return
}
