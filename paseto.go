package hppinjambackend

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

// <--- ini Login Admin, Login User & Register User --->
func LoginUser(Privatekey, MongoEnv, dbname, Colname string, r *http.Request) string {
	var resp Credential
	mconn := SetConnection(MongoEnv, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		if UserIsPasswordValid(mconn, Colname, datauser) {
			tokenstring, err := EncodeWithUsername(datauser.Username, os.Getenv(Privatekey))
			if err != nil {
				resp.Message = "Gagal Encode Token : " + err.Error()
			} else {
				resp.Status = true
				resp.Message = fmt.Sprintf("Selamat datang %s", datauser.Username)
				resp.Token = tokenstring
			}
		} else {
			resp.Message = "Password Salah"
		}
	}
	return GCFReturnStruct(resp)
}

func LoginAdmin(Privatekey, MongoEnv, dbname, Colname string, r *http.Request) string {
	var resp Credential
	mconn := SetConnection(MongoEnv, dbname)
	var dataadmin Admin
	err := json.NewDecoder(r.Body).Decode(&dataadmin)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		if AdminIsPasswordValid(mconn, Colname, dataadmin) {
			tokenstring, err := watoken.Encode(dataadmin.Username, os.Getenv(Privatekey))
			if err != nil {
				resp.Message = "Gagal Encode Token : " + err.Error()
			} else {
				resp.Status = true
				resp.Message = "Selamat Datang ADMIN"
				resp.Token = tokenstring
			}
		} else {
			resp.Message = "Password Salah"
		}
	}
	return GCFReturnStruct(resp)
}

// return struct
func GCFReturnStruct(DataStruct any) string {
	jsondata, _ := json.Marshal(DataStruct)
	return string(jsondata)
}

func ReturnStringStruct(Data any) string {
	jsonee, _ := json.Marshal(Data)
	return string(jsonee)
}

func Register(Mongoenv, dbname string, r *http.Request) string {
	resp := new(Credential)
	userdata := new(User)
	resp.Status = false
	conn := SetConnection(Mongoenv, dbname)
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		resp.Status = true
		hash, err := HashPass(userdata.Password)
		if err != nil {
			resp.Message = "Gagal Hash Password" + err.Error()
		}
		InsertUserdata(conn, userdata.Username, userdata.Email, userdata.Role, hash)
		resp.Message = "Berhasil Input data"
	}
	response := ReturnStringStruct(resp)
	return response
}

// <--- ini hp --->

// hp post
func GCFInsertHp(publickey, MONGOCONNSTRINGENV, dbname, colluser, collhp string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		userdata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			user2 := FindUser(mconn, colluser, userdata)
			if user2.Role == "user" {
				var datahp Hp
				err := json.NewDecoder(r.Body).Decode(&datahp)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					insertHp(mconn, collhp, Hp{
						Nomorid:     datahp.Nomorid,
						Title:       datahp.Title,
						Description: datahp.Description,
						Image:       datahp.Image,
						Status:      datahp.Status,
					})
					response.Status = true
					response.Message = "Berhasil Insert Hp"
				}
			} else {
				response.Message = "Anda tidak bisa Insert data karena bukan admin"
			}
		}
	}
	return GCFReturnStruct(response)
}

// delete hp
func GCFDeleteHp(publickey, MONGOCONNSTRINGENV, dbname, colladmin, collhp string, r *http.Request) string {

	var respon Credential
	respon.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var admindata Admin

	gettoken := r.Header.Get("token")
	if gettoken == "" {
		respon.Message = "Missing token in headers"
	} else {
		// Process the request with the "Login" token
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		admindata.Username = checktoken
		if checktoken == "" {
			respon.Message = "Invalid token"
		} else {
			admin2 := FindAdmin(mconn, colladmin, admindata)
			if admin2.Role == "admin" {
				var datahp Hp
				err := json.NewDecoder(r.Body).Decode(&datahp)
				if err != nil {
					respon.Message = "Error parsing application/json: " + err.Error()
				} else {
					DeleteHp(mconn, collhp, datahp)
					respon.Status = true
					respon.Message = "Berhasil Delete Hp"
				}
			} else {
				respon.Message = "Anda tidak bisa Delete data karena bukan admin"
			}
		}
	}
	return GCFReturnStruct(respon)
}

// update hp
func GCFUpdateHp(publickey, MONGOCONNSTRINGENV, dbname, colladmin, collhp string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var admindata Admin

	gettoken := r.Header.Get("token")
	if gettoken == "" {
		response.Message = "Missing token in Headers"
	} else {
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), gettoken)
		admindata.Username = checktoken
		if checktoken == "" {
			response.Message = "Invalid token"
		} else {
			admin2 := FindAdmin(mconn, colladmin, admindata)
			if admin2.Role == "admin" {
				var datahp Hp
				err := json.NewDecoder(r.Body).Decode(&datahp)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()

				} else {
					UpdatedHp(mconn, collhp, bson.M{"id": datahp.ID}, datahp)
					response.Status = true
					response.Message = "Berhasil Update Hp"
					GCFReturnStruct(CreateResponse(true, "Success Update Hp", datahp))
				}
			} else {
				response.Message = "Anda tidak bisa Update data karena bukan admin"
			}

		}
	}
	return GCFReturnStruct(response)
}

// get all hp
func GCFGetAllHp(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datahp := GetAllHp(mconn, collectionname)
	if datahp != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Hp", datahp))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Hp", datahp))
	}
}

// get all Hp by id
func GCFGetAllHpID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var datahp Hp
	err := json.NewDecoder(r.Body).Decode(&datahp)
	if err != nil {
		return err.Error()
	}

	hp := GetAllHpID(mconn, collectionname, datahp)
	if hp != (Hp{}) {
		return GCFReturnStruct(CreateResponse(true, "Success: Get ID Hp", datahp))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID Hp", datahp))
	}
}

func GetUserData(publicKey, MongoConnStringEnv, dbname, colname string, r *http.Request) string {
	req := new(Response)

	// Membuat koneksi ke MongoDB
	conn := SetConnection(MongoConnStringEnv, dbname)
	if conn == nil {
		req.Status = false
		req.Message = "Failed to connect to MongoDB"
		return ReturnStringStruct(req)
	}

	//Ambil token dari header Login
	tokenStr := r.Header.Get("Login")
	if tokenStr == "" {
		req.Status = false
		req.Message = "Header Login Not Found"
		return ReturnStringStruct(req)
	}

	// Verifikasi token menggunakan IsTokenValid
	payload, err := Decoder(publicKey, tokenStr)
	if err != nil {
		req.Status = false
		req.Message = "Invalid token: " + err.Error()
		return ReturnStringStruct(req)
	}

	fmt.Printf("Decode Result : %+v", payload)

	// Ambil username dari payload dengan type assertion
	username := payload.Username
	if username == "" {
		req.Status = false
		req.Message = "Username not found in token payload"
		return ReturnStringStruct(req)
	}

	// Mengambil data user dari database
	userData, err := GetUserFromDB(conn, colname, username)
	if err != nil {
		req.Status = false
		req.Message = "Failed to retrieve user data: " + err.Error()
		return ReturnStringStruct(req)
	}

	// Jika data user ditemukan
	req.Status = true
	req.Message = "User data retrieved successfully"
	req.Data = userData
	return ReturnStringStruct(req)
}
