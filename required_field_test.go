package rutil

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

type TestStruct struct {
	Name  string `rf:"required"`
	Email string `rf:"required"`
	Age   int
}

func TestCheckRequiredFields(t *testing.T) {
	tests := []struct {
		input         TestStruct
		expectedError error
	}{
		{
			input: TestStruct{
				Name:  "John Doe",
				Email: "john.doe@example.com",
				Age:   30,
			},
			expectedError: nil,
		},
		{
			input: TestStruct{
				Name:  "",
				Email: "john.doe@example.com",
				Age:   30,
			},
			expectedError: errors.New("missing required field(s): Name"),
		},
		{
			input: TestStruct{
				Name:  "John Doe",
				Email: "",
				Age:   30,
			},
			expectedError: errors.New("missing required field(s): Email"),
		},
		{
			input: TestStruct{
				Name:  "",
				Email: "",
				Age:   30,
			},
			expectedError: errors.New("missing required field(s): Name,Email"),
		},
	}

	for _, tt := range tests {
		err := CheckRequiredFields(tt.input)
		if tt.expectedError == nil {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, tt.expectedError.Error())
		}
	}
}
