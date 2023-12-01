package hppinjambackend

import (
	"encoding/json"
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
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(Privatekey))
			if err != nil {
				resp.Message = "Gagal Encode Token : " + err.Error()
			} else {
				resp.Status = true
				resp.Message = "Selamat Datang USER"
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

// <--- ini ticket --->

// ticket post
func GCFInsertTicket(publickey, MONGOCONNSTRINGENV, dbname, colluser, collticket string, r *http.Request) string {
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
				var dataticket Ticket
				err := json.NewDecoder(r.Body).Decode(&dataticket)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()
				} else {
					insertTicket(mconn, collticket, Ticket{
						Nomorid:     dataticket.Nomorid,
						Title:       dataticket.Title,
						Description: dataticket.Description,
						Image:       dataticket.Image,
						Status:      dataticket.Status,
					})
					response.Status = true
					response.Message = "Berhasil Insert Ticket"
				}
			} else {
				response.Message = "Anda tidak bisa Insert data karena bukan user"
			}
		}
	}
	return GCFReturnStruct(response)
}

// delete ticket
func GCFDeleteTicket(publickey, MONGOCONNSTRINGENV, dbname, colladmin, collticket string, r *http.Request) string {

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
				var dataticket Ticket
				err := json.NewDecoder(r.Body).Decode(&dataticket)
				if err != nil {
					respon.Message = "Error parsing application/json: " + err.Error()
				} else {
					DeleteTicket(mconn, collticket, dataticket)
					respon.Status = true
					respon.Message = "Berhasil Delete Ticket"
				}
			} else {
				respon.Message = "Anda tidak bisa Delete data karena bukan admin"
			}
		}
	}
	return GCFReturnStruct(respon)
}

// update ticket
func GCFUpdateTicket(publickey, MONGOCONNSTRINGENV, dbname, colladmin, collticket string, r *http.Request) string {
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
				var dataticket Ticket
				err := json.NewDecoder(r.Body).Decode(&dataticket)
				if err != nil {
					response.Message = "Error parsing application/json: " + err.Error()

				} else {
					UpdatedTicket(mconn, collticket, bson.M{"id": dataticket.ID}, dataticket)
					response.Status = true
					response.Message = "Berhasil Update Ticket"
					GCFReturnStruct(CreateResponse(true, "Success Update Ticket", dataticket))
				}
			} else {
				response.Message = "Anda tidak bisa Update data karena bukan admin"
			}

		}
	}
	return GCFReturnStruct(response)
}

// get all ticket
func GCFGetAllTicket(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	dataticket := GetAllTicket(mconn, collectionname)
	if dataticket != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Ticket", dataticket))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Ticket", dataticket))
	}
}

// get all ticket by id
func GCFGetAllTicketID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	var dataticket Ticket
	err := json.NewDecoder(r.Body).Decode(&dataticket)
	if err != nil {
		return err.Error()
	}

	ticket := GetAllTicketID(mconn, collectionname, dataticket)
	if ticket != (Ticket{}) {
		return GCFReturnStruct(CreateResponse(true, "Success: Get ID Ticket", dataticket))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed to Get ID Ticket", dataticket))
	}
}
