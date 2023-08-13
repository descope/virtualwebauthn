package test

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/require"
)

const ec2Cred = `
	{
		"id": "+Gco4xd4h+OQBTysFg7RxYNy61yJ/4LYeBeGxFGkV3g=",
		"key": {
			"type": "ec2",
			"data": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHVo9nWHBS2nduV3P4oKeVMiFnXxbwaNStIqmJsoYxTqhRANCAAQ7kDFjbS91S1oWz5nUtqsoi+7uyqChb1+SsIvUTLAfWBx7CRibtWJj0v47A83ve34+g6uaplwpWuShn5azl0AL"
		}
	}`

const rsaCred = `
	{
		"id": "DNxq+RGk3MkHqPN8FHyrTFsZkD8ov7z3gZR2JH6xQto=",
		"key": {
			"type": "rsa",
			"data": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2nOEyQzYy+WlCOBd1yeXUySG4IwGgUAbViR4NuZ35QuhmhXgrqULj+QppEY9fE1y4aZJlu6ZwJXCN/EzlebM8C0KoiL/TEkQs+NpJQk6ScMW/KStTfejcxG7YmGlQmcdBCB6gWJeLBwx7oeEXfprDK+XkWBIBYNk73w0H5XAwV7qKQdtI+80qathqK0cc2eZWIFMDH6a0XjnyYPnLih4OxcztKkd8V/dHPMNIq1XaqJanwjfm0PMvVrv341KKfL9BbsJSy0f7j10Y35CbvJnRiTDrpw6O7GhTVlgkjER+67/wRfDjUfZmjyAaH1rVF75qxHOHpnTq6x8d/xV/LFjHAgMBAAECggEASo2Z0u9lvUHeG07TJR+cWVcUER0ZmN2TLLKiNnBFcnJCdzieaxTbXj9aZLLqmaJKBG/1eNs3hCmE3jLXIgihiC4AtNW/muimNMYUODx934Ny+CxSp++LljYMGxl+RY3Cr2YlOslwdS4XhpH8V580h+HwJV1fXHixt6PEqiiduN4mpYNWzbHGn9VMoXImk/D10YJ1K44coC0SgyuY/2s5lT7nzrDt3CVdOwgH6E7bFpNjQOCkkoPlGjD9pBTWGdHUbeVyT21y4ji2dpnz32CoH5hLELaGhyX9ftc8liDj863OhcmipgmOtQesR6CMyvO9fmxTihBD7IrJEWWBq4QAQQKBgQDv7nZoyoTbu/BRipXUmtV/0haVZUzfsTRvHz1FI6DtugAQJZUPt5MA2fghXP8iM/75dWjzE+Suo+SSVC6n7gyAEPL7+4DL5sujn/1YRMVtFEl9LEP6PnY1M/DhLjuzQRfVKy2XKBCLQml9WdtV1QIO+e2k5cC7mmCI52OmncTd+QKBgQDC17WXTTQKe/N2FYU4Rsbhf2eOttwm+eKeir9RMmoUHs30re8JVax+Zxgh773GN+FbyaNZYkjZ0rAgVESfwTfjpVj71ioL3xK1/vvqQKXj59di1NefzIitxplKSTKBDA7CDXcvD8H3Ye7lAZZz9Hu2sRR7hYBmQdGuK3IIL/+cvwKBgQCL0jvO9bZXFz8FRe3q6BBjXNssVMxnz6zu1RWvpQOzhiFjR4OGlURlyqB/UOKd3A9K8NEoVv99hqU9YTGPS3qdZ0My9W4pZWZnBGVveyRSXPA2sgUrYBsjBhHqKDdCTzzETVVUMVTy0tEG68aWTnvUnnGPFxUqPtzi63V3M5n2gQKBgQCmiVldCVAB5hAiTiKgB17WPt90zDc/2TYp7M25yS2CJRJEoKY/hEr7f4LQ/ulmEz08BwznyWobREnmWCCPq8bpfNqh5lvp6bFEfb00bC1erzsZ7nKe02O/pJBBPm88feHfW0MTppRTrhFTDBhc5AsaDCFFssYcoQVnqRq+hMgmYQKBgCBGSN2lYf8vdB9OR4OPOaMPEm78e2C7rD17Yx85bAuAysAn/0VKrsiJA/Y3O4LiWs5OlC70YHYbQUuiG6LbyalIAF5J51KeBMi+Hq9Fw7+ofafGEDHYfEOSiUl47eGu2+9poQPYj2zP+d74Ca+fHqo8BjjRFUMscUwrOzPI+fAo"
		}
	}`

func TestMarshalledEC2Key(t *testing.T) {
	testMarshalledCredential(t, ec2Cred)
}

func TestMarshalledRSAKey(t *testing.T) {
	testMarshalledCredential(t, rsaCred)
}

func testMarshalledCredential(t *testing.T, credString string) {
	var cred virtualwebauthn.Credential
	err := json.Unmarshal([]byte(credString), &cred)
	require.NoError(t, err)
	testCredential(t, cred)

	bytes, err := json.Marshal(cred)
	require.NoError(t, err)

	trimmedString := regexp.MustCompile(`\s+`).ReplaceAllString(credString, "")
	require.Equal(t, trimmedString, string(bytes))

	var unmarshalledCred virtualwebauthn.Credential
	err = json.Unmarshal(bytes, &unmarshalledCred)
	require.NoError(t, err)
	testCredential(t, unmarshalledCred)

	require.Equal(t, cred.ID, unmarshalledCred.ID)
	require.Equal(t, cred.Key, unmarshalledCred.Key)
}
