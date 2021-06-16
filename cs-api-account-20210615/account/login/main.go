package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"golang.org/x/crypto/pbkdf2"
	"os"
)

type LoginRequestDto struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserDto struct {
	Pk       string
	Email    string
	Password string
	UserType string
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
	var buf bytes.Buffer

	loginRequest := LoginRequestDto{}
	err := json.Unmarshal([]byte(request.Body), &loginRequest)
	if err != nil {
		return Response{StatusCode: 500}, err
	}

	fmt.Println(loginRequest)

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	svc := dynamodb.New(sess)

	existingUser, err := svc.Query(&dynamodb.QueryInput{
		IndexName: aws.String("emailIdx"),
		TableName: aws.String(os.Getenv("CS_DB")),
		KeyConditions: map[string]*dynamodb.Condition{
			"email": {
				ComparisonOperator: aws.String(dynamodb.ComparisonOperatorEq),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: aws.String(loginRequest.Email),
					},
				},
			},
			"Sk": {
				ComparisonOperator: aws.String(dynamodb.ComparisonOperatorEq),
				AttributeValueList: []*dynamodb.AttributeValue{
					{
						S: aws.String("ACC"),
					},
				},
			},
		},
		FilterExpression: aws.String("#verified = :verified"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":verified": {S: aws.String("yes")},
		},
		ExpressionAttributeNames: map[string]*string{
			"#verified": aws.String("Verified"),
		},
	})

	if err != nil {
		return Response{StatusCode: 500}, err
	}

	if len(existingUser.Items) == 1 {
		fmt.Println("User Found")
		fmt.Println(existingUser.Items)
		user := UserDto{}
		err = dynamodbattribute.UnmarshalMap(existingUser.Items[0], &user)
		if err != nil {
			return Response{StatusCode: 500}, nil
		}
		fmt.Println(user)
		salt := user.Password[0:66]
		encoded := user.Password[66:len(user.Password)]

		temp := pbkdf2.Key([]byte(loginRequest.Password), []byte(salt), 10000, 50, sha256.New)
		if encoded == fmt.Sprintf("%x", temp) {
			fmt.Println("Password Match")
			body, err := json.Marshal(map[string]interface{}{
				"token": base64.StdEncoding.EncodeToString([]byte("abc-654")),
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
			return resp, nil
		}
	}

	return Response{StatusCode: 401}, err
}

func main() {
	lambda.Start(Handler)
}
