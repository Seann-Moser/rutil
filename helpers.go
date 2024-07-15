package rutil

import (
	"errors"
	"fmt"
	"github.com/gobeam/stringy"
	"reflect"
	"strings"
)

func Flag(name ...string) string {
	s := stringy.New(strings.Join(name, "-"))
	return s.KebabCase("?", "", "#", "").ToLower()
}

func FlagDescription(description string, name ...string) string {
	return fmt.Sprintf("%s [%s]", description, strings.ToUpper(Flag(name...)))
}

func CheckRequiredFields[T any](i T) error {
	v := reflect.ValueOf(i)
	t := reflect.TypeOf(i)
	var missingFieldNames []string
	for j := 0; j < t.NumField(); j++ {
		field := t.Field(j)
		tag := field.Tag.Get("ru")
		if tag == "required" {
			value := v.Field(j).Interface()
			if isEmpty(value) {
				missingFieldNames = append(missingFieldNames, field.Name)
			}
		}
	}
	if len(missingFieldNames) > 0 {
		return errors.New("missing required field(s): " + strings.Join(missingFieldNames, ","))
	}
	return nil
}

func isEmpty(value interface{}) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String, reflect.Array, reflect.Slice, reflect.Map, reflect.Chan:
		return v.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}
func MapKeys[K comparable, V any](data map[K]V) []K {
	var keyList []K
	for k := range data {
		keyList = append(keyList, k)
	}
	return keyList
}
