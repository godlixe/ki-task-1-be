package helper

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"gopkg.in/gomail.v2"
)

func SendMail(email string, subject string, content string) error {

	mailHost := os.Getenv("SMTP_HOST")
	mailPortStr := os.Getenv("SMTP_PORT")
	mailAccount := os.Getenv("EMAIL_SENDER")
	mailPassword := os.Getenv("EMAIL_PASSWORD")

	mailPortInt, err := strconv.Atoi(mailPortStr)
	if err != nil {
		log.Print(err.Error())
	}

	msg := gomail.NewMessage()
	msg.SetHeader("From", mailAccount)
	msg.SetHeader("To", email)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", content)

	dialer := gomail.NewDialer(mailHost, mailPortInt, mailAccount, mailPassword)

	if err := dialer.DialAndSend(msg); err != nil {
		log.Print(err.Error())
		fmt.Println(err)
		return err
	}

	log.Print("sent, :", dialer)
	return nil
}
