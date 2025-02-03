package hppinjambackend

import (
	"context"
	"fmt"
	"os"

	"github.com/aiteung/atdb"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetConnection(MONGOCONNSTRINGENV, dbname string) *mongo.Database {
	var DBmongoinfo = atdb.DBInfo{
		// DBString: "mongodb+srv://daffaaud:UQWcHgtx3Ar2TyY6@proyek-2.gb5yaav.mongodb.net/test", //os.Getenv(MONGOCONNSTRINGENV),
		DBString: os.Getenv(MONGOCONNSTRINGENV),
		DBName:   dbname,
	}
	return atdb.MongoConnect(DBmongoinfo)
}

func InsertUserdata(MongoConn *mongo.Database, username, email, role, password string) (InsertedID interface{}) {
	req := new(User)
	req.Username = username
	req.Email = email
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "user", req)
}

func InsertAdmindata(MongoConn *mongo.Database, username, email, role, password string) (InsertedID interface{}) {
	req := new(Admin)
	req.Username = username
	req.Email = email
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "admin", req)
}

func DeleteUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	filter := bson.M{"username": userdata.Username}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func DeleteAdmin(mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	filter := bson.M{"username": admindata.Username}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func FindUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindAdmin(mongoconn *mongo.Database, collection string, admindata Admin) Admin {
	filter := bson.M{"username": admindata.Username}
	return atdb.GetOneDoc[Admin](mongoconn, collection, filter)
}

func UserIsPasswordValid(mongoconn *mongo.Database, collection string, userdata User) bool {
	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mongoconn, collection, filter)
	return CompareHashPass(userdata.Password, res.Password)
}

func AdminIsPasswordValid(mongoconn *mongo.Database, collection string, admindata Admin) bool {
	filter := bson.M{"username": admindata.Username}
	res := atdb.GetOneDoc[Admin](mongoconn, collection, filter)
	return CompareHashPass(admindata.Password, res.Password)
}

func MongoCreateConnection(MongoString, dbname string) *mongo.Database {
	MongoInfo := atdb.DBInfo{
		DBString: os.Getenv(MongoString),
		DBName:   dbname,
	}
	conn := atdb.MongoConnect(MongoInfo)
	return conn
}

func InsertOneDoc(db *mongo.Database, collection string, doc interface{}) (insertedID interface{}) {
	insertResult, err := db.Collection(collection).InsertOne(context.TODO(), doc)
	if err != nil {
		fmt.Printf("InsertOneDoc: %v\n", err)
	}
	return insertResult.InsertedID
}

func GetOneAdmin(MongoConn *mongo.Database, colname string, admindata Admin) Admin {
	filter := bson.M{"username": admindata.Username}
	data := atdb.GetOneDoc[Admin](MongoConn, colname, filter)
	return data
}

func GetUserFromDB(mconn *mongo.Database, Colname, username string) (User, error) {
	var user User
	collection := mconn.Collection(Colname)

	err := collection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		return User{}, err
	}

	return user, nil
}
