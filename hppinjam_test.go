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
	userdata.Username = "farhan"
	userdata.Email = "farhanriziq@gmail.com"
	userdata.Password = "riziq"
	userdata.Role = "user"
	mconn := SetConnection("MONGOSTRING", "Fitness")
	CreateNewUserRole(mconn, "user", userdata)
}

// admin
func TestCreateNewAdminRole(t *testing.T) {
	var admindata Admin
	admindata.Username = "admin"
	admindata.Email = "admin@gmail.com"
	admindata.Password = "admin"
	admindata.Role = "admin"
	mconn := SetConnection("MONGOSTRING", "Fitness")
	CreateNewAdminRole(mconn, "admin", admindata)
}

// user
func TestDeleteUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var userdata User
	userdata.Email = "farhanriziq@gmail.com"
	DeleteUser(mconn, "user", userdata)
}

// admin
func TestDeleteAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var admindata Admin
	admindata.Username = "farhan"
	DeleteAdmin(mconn, "admin", admindata)
}

// user
func CreateNewUserToken(t *testing.T) {
	var userdata User
	userdata.Username = "farhan"
	userdata.Email = "farhanriziq@gmail.com"
	userdata.Password = "riziq"
	userdata.Role = "user"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "hppinjam")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

// admin
func CreateNewAdminToken(t *testing.T) {
	var admindata Admin
	admindata.Username = "farhan"
	admindata.Email = "farhanriziq@gmail.com"
	admindata.Password = "riziq"
	admindata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "hppinjam")

	// Call the function to create a admin and generate a token
	err := CreateAdminAndAddToken("your_private_key_env", mconn, "admin", admindata)

	if err != nil {
		t.Errorf("Error creating admin and token: %v", err)
	}
}

// user
func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var userdata User
	userdata.Username = "farhan"
	userdata.Email = "farhanriziq@gmail.com"
	userdata.Password = "riziq"
	userdata.Role = "user"
	CreateNewUserRole(mconn, "user", userdata)
}

// admin
func TestGFCPostHandlerAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var admindata Admin
	admindata.Username = "farhan"
	admindata.Email = "farhanriziq@gmail.com"
	admindata.Password = "riziq"
	admindata.Role = "admin"
	CreateNewAdminRole(mconn, "admin", admindata)
}

// Test Insert Hp
func TestInsertHp(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var hpdata Hp
	hpdata.Nomorid = 1
	hpdata.Title = "Iphone 15 Pro Max"
	hpdata.Description = "Hp keluaran terbaru dari iphone yang memiliki spesifikasi yang sangat amat bagus"
	hpdata.Image = "https://cdn.eraspace.com/media/catalog/product/a/p/apple_iphone_15_pro_max_natural_titanium_1_1_2.jpg"
	CreateNewHp(mconn, "hp", hpdata)
}

// Test All Hp
func TestAllHp(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	hp := GetAllHp(mconn, "hp")
	fmt.Println(hp)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "riziq"
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
	hasil, err := watoken.Encode("hppinjam", privateKey)
	fmt.Println(hasil, err)
}

// user
func TestHashFunctionUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var userdata User
	userdata.Username = "farhan"
	userdata.Email = "farhanriziq@gmail.com"
	userdata.Password = "riziq"

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
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var admindata Admin
	admindata.Username = "farhan"
	admindata.Email = "farhanriziq@gmail.com"
	admindata.Password = "riziq"

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
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var userdata User
	userdata.Username = "farhan"
	userdata.Email = "farhanriziq@gmail.com"
	userdata.Password = "riziq"

	anu := UserIsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}

// admin
func TestAdminIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var admindata Admin
	admindata.Username = "farhan"
	admindata.Email = "farhanriziq@gmail.com"
	admindata.Password = "riziq"

	anu := AdminIsPasswordValid(mconn, "admin", admindata)
	fmt.Println(anu)
}

// user
func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var userdata User
	userdata.Username = "farhan"
	userdata.Email = "farhanriziq@gmail.com"
	userdata.Password = "riziq"
	userdata.Role = "user"
	CreateUser(mconn, "user", userdata)
}

// admin
func TestAdminFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var admindata Admin
	admindata.Email = "hppinjam@gmail.com"
	admindata.Password = "hppinjam"
	admindata.Role = "admin"
	CreateAdmin(mconn, "admin", admindata)
}

// user
func TestLoginUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var userdata User
	userdata.Username = "farhan"
	userdata.Email = "farhanriziq@gmail.com"
	userdata.Password = "riziq"
	UserIsPasswordValid(mconn, "user", userdata)
	fmt.Println(userdata)
}

// admin
func TestLoginAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "hppinjam")
	var admindata Admin
	admindata.Username = "farhan"
	admindata.Email = "farhanriziq@gmail.com"
	admindata.Password = "riziq"
	AdminIsPasswordValid(mconn, "admin", admindata)
	fmt.Println(admindata)
}
