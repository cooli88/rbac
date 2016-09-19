package rbac

import (
	"errors"
	"reflect"
)

// all roles
const (
	admin string = "admin"
	manager string = "manager"
	moderator string = "moderator"
	customer string = "customer"
	guest string = "guest"
)

var (
	//Roles переменная со всеми доступными ролями
	Roles roles = roles{admin, manager, moderator, customer, guest}

	//Возможные ошибки
	errorAlreadyLogged = errors.New("You already logged")
	errorAlowedAccess = errors.New("Not alowed access")
	errorItIsNotRole = errors.New("It is not role")
)

type AlowedRoles map[string]bool

type roles struct {
	admin     string
	manager   string
	moderator string
	customer  string
	guest     string
}

//Admin return role admin
func (r roles)Admin() string {
	return r.admin
}

//Manager return role manager
func (r roles)Manager() string {
	return r.manager
}

//Moderator return role moderator
func (r roles)Moderator() string {
	return r.moderator
}

//Customer return role customer
func (r roles)Customer() string {
	return r.customer
}

//NotLogged return role notLogged
func (r roles)Guest() string {
	return r.guest
}

//LoggedUsers return roles logged user
func (r roles)LoggedOnUsers() AlowedRoles {
	return AlowedRoles{r.admin:true, r.customer:true, r.moderator:true, r.manager:true, }
}

//LoggedUsers return roles logged user
func (r roles)StaffUsers() AlowedRoles {
	return AlowedRoles{r.admin:true, r.moderator:true, r.manager:true, }
}

//LoggedUsers return roles logged user
func (r roles)StaffManagersUsers() AlowedRoles {
	return AlowedRoles{r.admin:true, r.manager:true, }
}

//LoggedUsers return roles logged user
func (r roles)AdminsUsers() AlowedRoles {
	return AlowedRoles{r.admin:true}
}

//NotLoggedUsers return roles not logged user
func (r roles)GuestUsers() AlowedRoles {
	return AlowedRoles{r.guest:true}
}

//AllUsers return all possible user roles
func (r roles)AllUsers() AlowedRoles {
	return AlowedRoles{r.admin:true, r.customer:true, r.manager:true, r.moderator:true, r.guest:true}
}

//AllClient return empty map
func (roles)AllClient() AlowedRoles {
	return AlowedRoles{}
}

//CheckRoleAccess checks the access for this role
func CheckRoleAccess(alowedRoles AlowedRoles, role string) error {
	if len(alowedRoles) == 0 {
		return nil
	}

	if !checkItIsRole(role) {
		return errorItIsNotRole
	} else if checkUserAlredyLogged(alowedRoles, role) {
		return errorAlreadyLogged
	} else if alowedRoles[role] != true {
		return errorAlowedAccess
	}

	return nil
}

//checkUserAlredyLogined checks the user is logged on
func checkUserAlredyLogged(alowedRoles AlowedRoles, role string) bool {
	if reflect.DeepEqual(Roles.GuestUsers(), alowedRoles) && alowedRoles[role] != true {
		return true
	}
	return false
}

func checkItIsRole(role string) bool {
	allUser := Roles.AllUsers()
	return allUser[role]
}
