package hppinjambackend

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

// user
func TestCreateNewUserRole(t *testing.T) {
	var userdata User
	userdata.Username = "prisyahaura"
	userdata.Email = "prisyahaura@gmail.com"
	userdata.Password = "picaw"
	userdata.Role = "user"
	mconn := SetConnection("MONGOSTRING", "wegotour")
	CreateNewUserRole(mconn, "user", userdata)
}

// admin
func TestCreateNewAdminRole(t *testing.T) {
	var admindata Admin
	admindata.Username = "prisyahaura"
	admindata.Email = "prisyahaura@gmail.com"
	admindata.Password = "picaw"
	admindata.Role = "admin"
	mconn := SetConnection("MONGOSTRING", "wegotour")
	CreateNewAdminRole(mconn, "admin", admindata)
}

// user
func TestDeleteUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Email = "prisyahaura@gmail.com"
	DeleteUser(mconn, "user", userdata)
}

// admin
func TestDeleteAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var admindata Admin
	admindata.Username = "prisyahaura"
	DeleteAdmin(mconn, "admin", admindata)
}

// user
func CreateNewUserToken(t *testing.T) {
	var userdata User
	userdata.Username = "prisyahaura"
	userdata.Email = "prisyahaura@gmail.com"
	userdata.Password = "picaw"
	userdata.Role = "user"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "wegotour")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

// admin
func CreateNewAdminToken(t *testing.T) {
	var admindata Admin
	admindata.Username = "prisyahaura"
	admindata.Email = "prisyahaura@gmail.com"
	admindata.Password = "picaw"
	admindata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "wegotour")

	// Call the function to create a admin and generate a token
	err := CreateAdminAndAddToken("your_private_key_env", mconn, "admin", admindata)

	if err != nil {
		t.Errorf("Error creating admin and token: %v", err)
	}
}

// user
func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Username = "prisyahaura"
	userdata.Email = "prisyahaura@gmail.com"
	userdata.Password = "picaw"
	userdata.Role = "user"
	CreateNewUserRole(mconn, "user", userdata)
}

// admin
func TestGFCPostHandlerAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var admindata Admin
	admindata.Username = "prisyahaura"
	admindata.Email = "prisyahaura@gmail.com"
	admindata.Password = "picaw"
	admindata.Role = "admin"
	CreateNewAdminRole(mconn, "admin", admindata)
}

// Test Insert Ticket
func TestInsertTicket(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var ticketdata Ticket
	ticketdata.Nomorid = 1
	ticketdata.Title = "garut"
	ticketdata.Description = "waw garut keren banget"
	ticketdata.Image = "https://images3.alphacoders.com/165/thumb-1920-165265.jpg"
	CreateNewTicket(mconn, "ticket", ticketdata)
}

// Test All Ticket
func TestAllTicket(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	ticket := GetAllTicket(mconn, "ticket")
	fmt.Println(ticket)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "picaw"
	hash, _ := HashPass(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CompareHashPass(password, hash)
	fmt.Println("Match:   ", match)
}

// pasetokey
func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("wegotour", privateKey)
	fmt.Println(hasil, err)
}

// user
func TestHashFunctionUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Username = "prisyahaura"
	userdata.Email = "prisyahaura@gmail.com"
	userdata.Password = "picaw"

	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[Admin](mconn, "user", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPass(userdata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CompareHashPass(userdata.Password, res.Password)
	fmt.Println("Match:   ", match)
}

// admin
func TestHashFunctionAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var admindata Admin
	admindata.Username = "prisyahaura"
	admindata.Email = "prisyahaura@gmail.com"
	admindata.Password = "picaw"

	filter := bson.M{"username": admindata.Username}
	res := atdb.GetOneDoc[Admin](mconn, "admin", filter)
	fmt.Println("Mongo Admin Result: ", res)
	hash, _ := HashPass(admindata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CompareHashPass(admindata.Password, res.Password)
	fmt.Println("Match:   ", match)
}

// user
func TestUserIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Username = "prisyahaura"
	userdata.Email = "prisyahaura@gmail.com"
	userdata.Password = "picaw"

	anu := UserIsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}

// admin
func TestAdminIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var admindata Admin
	admindata.Username = "prisyahaura"
	admindata.Email = "prisyahaura@gmail.com"
	admindata.Password = "picaw"

	anu := AdminIsPasswordValid(mconn, "admin", admindata)
	fmt.Println(anu)
}

// user
func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Username = "prisyahaura"
	userdata.Email = "prisyahaura@gmail.com"
	userdata.Password = "picaw"
	userdata.Role = "user"
	CreateUser(mconn, "user", userdata)
}

// admin
func TestAdminFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var admindata Admin
	admindata.Email = "pasabar@gmail.com"
	admindata.Password = "hebat"
	admindata.Role = "admin"
	CreateAdmin(mconn, "admin", admindata)
}

// user
func TestLoginUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var userdata User
	userdata.Username = "prisyahaura"
	userdata.Email = "prisyahaura@gmail.com"
	userdata.Password = "picaw"
	UserIsPasswordValid(mconn, "user", userdata)
	fmt.Println(userdata)
}

// admin
func TestLoginAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "wegotour")
	var admindata Admin
	admindata.Username = "prisyahaura"
	admindata.Email = "prisyahaura@gmail.com"
	admindata.Password = "picaw"
	AdminIsPasswordValid(mconn, "admin", admindata)
	fmt.Println(admindata)
}
