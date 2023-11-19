package helper

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"
)

type Mail struct {
	Sender   string
	Receiver []string
	Subject  string
	Body     string
}

func SendEmail(mail Mail) error {
	sender := os.Getenv("EMAIL_SENDER")
	password := os.Getenv("EMAIL_PASSWORD")

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	mail.Sender = sender
	message := buildMessage(mail)

	auth := smtp.PlainAuth("", mail.Sender, password, smtpHost)
	address := fmt.Sprintf("%s:%s", smtpHost, smtpPort)

	err := smtp.SendMail(address, auth, mail.Sender, mail.Receiver, []byte(message))
	if err != nil {
		return err
	}

	return nil
}

func buildMessage(mail Mail) string {
	msg := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n"
	msg += fmt.Sprintf("From: %s\r\n", mail.Sender)
	msg += fmt.Sprintf("To: %s\r\n", strings.Join(mail.Receiver, ";"))
	msg += fmt.Sprintf("Subject: %s\r\n", mail.Subject)
	msg += fmt.Sprintf("\r\n%s\r\n", mail.Body)

	return msg
}
