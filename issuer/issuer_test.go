package issuer

import (
	"reflect"
	"testing"
	"time"
)

func TestAssertionIsAuthenticationOnlyContract(t *testing.T) {
	typ := reflect.TypeOf(Assertion{})
	want := map[string]reflect.Type{"Issuer": reflect.TypeOf(""), "Subject": reflect.TypeOf(""), "Name": reflect.TypeOf(""), "Email": reflect.TypeOf(""), "AMR": reflect.TypeOf([]string{}), "AAL": reflect.TypeOf(""), "AuthTime": reflect.TypeOf(time.Time{}), "ActingFor": reflect.TypeOf(""), "ClientID": reflect.TypeOf("")}
	if typ.NumField() != len(want) {
		t.Fatalf("Assertion fields = %d, want %d", typ.NumField(), len(want))
	}
	for name, fieldType := range want {
		field, ok := typ.FieldByName(name)
		if !ok || field.Type != fieldType {
			t.Errorf("%s has wrong type", name)
		}
	}
	for _, forbidden := range []string{"Groups", "Roles", "Scopes", "Entitlements", "Tenants"} {
		if _, ok := typ.FieldByName(forbidden); ok {
			t.Errorf("Assertion must not contain authorization field %s", forbidden)
		}
	}
}
