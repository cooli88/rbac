package rbac

import (
	"testing"
	"reflect"
)

const notRole = "adasdadada"

func TestCheckRoleAccess1(t *testing.T) {
	if Roles.Admin() != admin {
		t.Errorf("%v; want %v", Roles.Admin(), admin)
	}

	if Roles.Manager() != manager {
		t.Errorf("%v; want %v", Roles.Manager(), manager)
	}

	if Roles.Moderator() != moderator {
		t.Errorf("%v; want %v", Roles.Moderator(), moderator)
	}

	if Roles.Customer() != customer {
		t.Errorf("%v; want %v", Roles.Customer(), customer)
	}

	if Roles.Guest() != guest{
		t.Errorf("%v; want %v", Roles.Guest(), guest)
	}
}

func TestCheckRoleAccessLoggedOnUsers(t *testing.T) {
	tests := []struct {
		role string
		result interface{}
	}{
		{admin, nil},
		{manager, nil},
		{moderator, nil},
		{customer, nil},
		{guest, errorAlowedAccess},
		{notRole, errorItIsNotRole},
	}

	for _,test := range tests{
		err := CheckRoleAccess(Roles.LoggedOnUsers(), test.role)
		if !reflect.DeepEqual(err, test.result) {
			t.Errorf("%v; want %v", err, test.result)
		}
	}
}

func TestCheckRoleAccessStaffUsers(t *testing.T) {
	tests := []struct {
		role string
		result interface{}
	}{
		{admin, nil},
		{manager, nil},
		{moderator, nil},
		{customer, errorAlowedAccess},
		{guest, errorAlowedAccess},
		{notRole, errorItIsNotRole},
	}

	for _,test := range tests{
		err := CheckRoleAccess(Roles.StaffUsers(), test.role)
		if !reflect.DeepEqual(err, test.result) {
			t.Errorf("%v; want %v", err, test.result)
		}
	}
}

func TestCheckRoleAccessStaffManagersUsers(t *testing.T) {
	tests := []struct {
		role string
		result interface{}
	}{
		{admin, nil},
		{manager, nil},
		{moderator, errorAlowedAccess},
		{customer, errorAlowedAccess},
		{guest, errorAlowedAccess},
		{notRole, errorItIsNotRole},
	}

	for _,test := range tests{
		err := CheckRoleAccess(Roles.StaffManagersUsers(), test.role)
		if !reflect.DeepEqual(err, test.result) {
			t.Errorf("%v; want %v", err, test.result)
		}
	}
}

func TestCheckRoleAccessAdminsUsers(t *testing.T) {
	tests := []struct {
		role string
		result interface{}
	}{
		{admin, nil},
		{manager, errorAlowedAccess},
		{moderator, errorAlowedAccess},
		{customer, errorAlowedAccess},
		{guest, errorAlowedAccess},
		{notRole, errorItIsNotRole},
	}

	for _,test := range tests{
		err := CheckRoleAccess(Roles.AdminsUsers(), test.role)
		if !reflect.DeepEqual(err, test.result) {
			t.Errorf("%v; want %v", err, test.result)
		}
	}
}

func TestCheckRoleGuestUsers(t *testing.T) {
	tests := []struct {
		role string
		result interface{}
	}{
		{admin, errorAlreadyLogged},
		{manager, errorAlreadyLogged},
		{moderator, errorAlreadyLogged},
		{customer, errorAlreadyLogged},
		{guest, nil},
		{notRole, errorItIsNotRole},
	}

	for _,test := range tests{
		err := CheckRoleAccess(Roles.GuestUsers(), test.role)
		if !reflect.DeepEqual(err, test.result) {
			t.Errorf("%v; want %v", err, test.result)
		}
	}
}

func TestCheckRoleAllUsers(t *testing.T) {
	tests := []struct {
		role string
		result interface{}
	}{
		{admin, nil},
		{manager, nil},
		{moderator, nil},
		{customer, nil},
		{guest, nil},
		{notRole, errorItIsNotRole},
	}

	for _,test := range tests{
		err := CheckRoleAccess(Roles.AllUsers(), test.role)
		if !reflect.DeepEqual(err, test.result) {
			t.Errorf("%v; want %v", err, test.result)
		}
	}
}

func TestCheckRoleAllClient(t *testing.T) {
	tests := []struct {
		role string
		result interface{}
	}{
		{admin, nil},
		{manager, nil},
		{moderator, nil},
		{customer, nil},
		{guest, nil},
		{notRole, nil},
	}

	for _,test := range tests{
		err := CheckRoleAccess(Roles.AllClient(), test.role)
		if !reflect.DeepEqual(err, test.result) {
			t.Errorf("%v; want %v", err, test.result)
		}
	}
}
