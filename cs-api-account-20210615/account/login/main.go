package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	"github.com/mergermarket/go-pkcs7"
	_ "github.com/mergermarket/go-pkcs7"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
	"time"
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

type SessionTokenDto struct {
	OwnerId string `json:"owner_id"`
	Email   string `json:"email"`
	Exp     int64  `json:"exp"`
}

var sharedKey = []byte("s344rethaaaaycfftainch@r$32chars")

const CIPHER_KEY = "s344rethaaaaycfftainch@r$32chars"

var iv = []byte{15, 42, 27, 34, 84, 45, 54, 34, 86, 45, 84, 98, 63, 35, 16, 13}

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
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	svc := dynamodb.New(sess)

	existingUser, err := svc.Query(&dynamodb.QueryInput{
		IndexName: aws.String("emailIdx"),
		TableName: aws.String(os.Getenv("CLASSIFY_RENTALS_DB")),

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
		user := UserDto{}
		err = dynamodbattribute.UnmarshalMap(existingUser.Items[0], &user)
		if err != nil {
			return Response{StatusCode: 500}, nil
		}

		salt := user.Password[0:66]
		encoded := user.Password[66:len(user.Password)]

		temp := pbkdf2.Key([]byte(loginRequest.Password), []byte(salt), 10000, 50, sha256.New)
		if encoded == fmt.Sprintf("%x", temp) {
			fmt.Println("Password Match")

			sessionToken := SessionTokenDto{
				OwnerId: user.OwnerId,
				Email:   user.Email,
				Exp:     time.Now().Add(time.Minute * 15).Unix(),
			}

			sessionTokenMarshalled, err := json.Marshal(&sessionToken)
			if err != nil {
				fmt.Println(err)
				return Response{StatusCode: 500}, err
			}

			//encryptedSessionToken := Encrypt("a=s@eiyu$#wp*a=sa=s@eiyu$#wp*a=s", string(sessionTokenMarshalled))
			encryptedSessionToken, err := Encrypt2(string(sessionTokenMarshalled))
			if err != nil {
				return Response{StatusCode: 500}, err
			}

			body, err := json.Marshal(map[string]interface{}{
				"token": encryptedSessionToken,
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

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func Encrypt(key, text string) string {
	fmt.Println("Encrypting: ", text)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	plaintext := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	return encodeBase64(ciphertext)
}

func Encrypt2(unencrypted string) (string, error) {
	key := []byte(CIPHER_KEY)
	plainText := []byte(unencrypted)
	plainText, err := pkcs7.Pad(plainText, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf(`plainText: %s has error`, plainText)
	}
	if len(plainText)%aes.BlockSize != 0 {
		return "", fmt.Errorf(`plainText: %s invalid block size`, plainText)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return fmt.Sprintf("%x", cipherText), nil

}

func Decrypt(key, text string) string {
	fmt.Println(text)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	ciphertext := decodeBase64(text)
	cfb := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)

	return string(plaintext)
}
