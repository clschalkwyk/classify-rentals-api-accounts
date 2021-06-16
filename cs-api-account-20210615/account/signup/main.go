package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/ses"
	uuid "github.com/satori/go.uuid"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

type Item struct {
	Pk       string
	Sk       string
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	UserType string `json:"userType"`
	Created  string
	Verified string
	OwnerId  string
}

// Response is of type APIGatewayProxyResponse since we're leveraging the
// AWS Lambda Proxy Request functionality (default behavior)
//
// https://serverless.com/framework/docs/providers/aws/events/apigateway/#lambda-proxy-integration
type Response events.APIGatewayProxyResponse

// Handler is our lambda handler invoked by the `lambda.Start` function call
func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (Response, error) {
	tableName := os.Getenv("CS_DB")
	var buf bytes.Buffer

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := dynamodb.New(sess)
	newAccount := Item{
		Pk:       uuid.NewV4().String(),
		Sk:       "ACC",
		Email:    "",
		UserType: "",
		Password: "",
		Created:  time.Now().Format(time.RFC3339),
		Verified: "no",
	}
	err := json.Unmarshal([]byte(request.Body), &newAccount)
	if err != nil {
		return Response{Body: err.Error(), StatusCode: 500}, nil
	}
	av, err := dynamodbattribute.MarshalMap(newAccount)
	if err != nil {
		log.Fatalf("got error marshaling data: %s", err)
	}
	// Search for existing user
	result, err := svc.Query(&dynamodb.QueryInput{
		IndexName: aws.String("emailIdx"),
		TableName: aws.String(os.Getenv("CS_DB")),
		KeyConditions: map[string]*dynamodb.Condition{
			"email": {
				ComparisonOperator: aws.String("EQ"),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: aws.String(newAccount.Email),
					},
				},
			},
		},
	})

	if err != nil {
		return Response{Body: err.Error(), StatusCode: 500}, nil
	}
	if len(result.Items) > 0 {
		fmt.Println("has existing account")
		respond, err := json.Marshal(map[string]interface{}{
			"message": "Account creation failed",
			"status":  500,
		})
		if err != nil {
			log.Fatalf("Error marshaling response: %s ", err)
		}
		return Response{Body: string(respond), StatusCode: 200}, nil
	}
	// if existing, error
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}
	_, err = svc.PutItem(input)
	if err != nil {
		log.Fatalf("Error adding item: %s", err)
	}

	body, err := json.Marshal(map[string]interface{}{
		"message": "New Account Created",
		"status":  200,
	})

	if err != nil {
		return Response{StatusCode: 404}, err
	}
	json.HTMLEscape(&buf, body)

	resp := Response{
		StatusCode:      200,
		IsBase64Encoded: false,
		Body:            buf.String(),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	sendVerifyEmail(newAccount)
	return resp, nil
}

func main() {
	lambda.Start(Handler)
}

const (
	CharSet = "UTF-8"
	Sender  = "hello@cyberstaffing.co.za"
)

func sendVerifyEmail(newAccount Item) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("af-south-1"),
	})
	if err != nil {
		log.Fatalf("Error setting up session for ses: %s", err)
	}

	svc := ses.New(sess)
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: []*string{
				aws.String(newAccount.Email),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: aws.String(CharSet),
					Data:    aws.String("Please follow the link to verify your account:"),
				},
				Text: &ses.Content{
					Charset: aws.String(CharSet),
					Data:    aws.String("Please follow the link to verify your account:"),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String(CharSet),
				Data:    aws.String("Welcome to CyberStaffing!"),
			},
		},
		Source: aws.String(Sender),
	}
	result, err := svc.SendEmail(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ses.ErrCodeMessageRejected:
				fmt.Println(ses.ErrCodeMessageRejected, aerr.Error())
			case ses.ErrCodeMailFromDomainNotVerifiedException:
				fmt.Println(ses.ErrCodeMailFromDomainNotVerifiedException, aerr.Error())
			case ses.ErrCodeConfigurationSetDoesNotExistException:
				fmt.Println(ses.ErrCodeConfigurationSetDoesNotExistException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}

		return
	}
	fmt.Println(result)
	fmt.Println("Sent mail")
}
