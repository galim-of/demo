package dbl

import (
	"context"
	"demo/utils"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type params struct {
	accessTTL  int64
	refreshTTL int64
	jwtSecret  string
	uri        string
}

var db *DBlayer

func init() {
	var p params
	p.uri = os.Getenv("URI")
	p.jwtSecret = os.Getenv("JWT_SECRET")

	accessTTL, err := strconv.ParseInt(os.Getenv("ACCSESS_TTL"), 10, 64)
	utils.CloseApp(err, "Check that ACCSESS_TTL specified")
	refreshTTL, err := strconv.ParseInt(os.Getenv("REFRESH_TTL"), 10, 64)
	utils.CloseApp(err, "Check that REFRESH_TTL specified")

	client, err := mongo.NewClient(options.Client().ApplyURI(p.uri))
	utils.CloseApp(err)

	ctx, _ := context.WithTimeout(context.Background(), 300*time.Second)
	// ctx := context.TODO()
	err = client.Connect(ctx)
	utils.CloseApp(err)

	err = client.Ping(ctx, readpref.Primary())
	utils.CloseApp(err)
	fmt.Println("Successfully connected and pinged.")
	p.accessTTL = accessTTL
	p.refreshTTL = refreshTTL
	db = NewDBLayer(ctx, client, &p)

}

//DBlayer wrapper on mongo.Client
type DBlayer struct {
	client *mongo.Client
	ctx    context.Context
	p      *params
}

type user struct {
	GUID      primitive.ObjectID `bson:"_id,omitempty"`
	FirstName string             `bson:"firstName,omitempty"`
	LastName  string             `bson:"lastName,omitempty"`
	Password  []byte             `bson:"hash,omitempty"`
}

type customClaims struct {
	GUID string
	jwt.StandardClaims
}

//NewDBLayer ...
func NewDBLayer(c context.Context, cl *mongo.Client, p *params) *DBlayer {
	return &DBlayer{
		ctx:    c,
		client: cl,
		p:      p,
	}
}

//Close calls client.Disconnect()
func Close() error {
	return db.client.Disconnect(db.ctx)
}

func RegisterUser(firstName, lastName, password string) (id string, err error) {
	tmp, err := db.registerUser(firstName, lastName, password)
	id = tmp.String()
	return id, err

}

func AuthenticateUser(guid string, password string) (map[string]string, error) {
	return db.authenticateUser(guid, password)
}

func (db *DBlayer) registerUser(firstName, lastName, password string) (id primitive.ObjectID, err error) {
	coll := db.client.Database("test").Collection("users")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return id, err
	}
	//TODO Must use transaction?
	user := user{FirstName: firstName, LastName: lastName, Password: hashedPassword}
	res, err := coll.InsertOne(db.ctx, user)
	if err != nil {
		log.Printf("Can't register user %s %s: %s\n", firstName, lastName, err)
		return id, err
	}
	id = res.InsertedID.(primitive.ObjectID)
	fmt.Printf("Successfully registered user %s %s with id = %s\n", firstName, lastName, id)
	return id, err
}

func (db *DBlayer) userExist(guid primitive.ObjectID) (ok bool, err error) {
	//TODO Must use transaction
	coll := db.client.Database("test").Collection("users")
	var user user
	err = coll.FindOne(db.ctx, bson.M{"_id": guid}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		//GUID does not exist
		return false, nil
	}
	if err != nil {
		return ok, err
	}
	ok = true
	return
}

func (db *DBlayer) authenticateUser(guid string, password string) (tokensMap map[string]string, err error) {
	id, err := primitive.ObjectIDFromHex(guid)
	if err != nil {
		return nil, errors.New("Check that GUID correspond to ObjectID. See https://docs.mongodb.com/manual/reference/bson-types/#objectid")
	}

	ok, err := db.userExist(id)
	if err != nil {
		return nil, errors.New("Error occured on the server-side: " + err.Error() + " Repeat again later")
	}
	if !ok {
		return nil, errors.New("GUID or password incorrect. Try again")
	}
	//TODO Must use transaction
	coll := db.client.Database("test").Collection("users")
	var user user
	err = coll.FindOne(db.ctx, bson.M{"_id": id}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		return nil, errors.New("GUID or password incorrect. Try again")
	}
	if err != nil {
		return nil, errors.New("Error occured on the server-side: " + err.Error() + " Repeat again later")
	}

	now := time.Now()
	issuedAt := now.Unix()
	expiresIn := now.Add(time.Second * time.Duration(db.p.accessTTL)).Unix()
	claims := customClaims{
		guid,
		jwt.StandardClaims{
			IssuedAt:  issuedAt,
			ExpiresAt: expiresIn,
		},
	}
	accsess, err := makeAccsessToken(claims)
	if err != nil {
		return nil, errors.New("Can't make accsess token: " + err.Error())
	}
	refresh, err := makeRefreshToken()
	if err != nil {
		return nil, errors.New("Can't make refresh token: " + err.Error())
	}
	t := tokens{GUID: id, AccessTk: accsess, RefreshTk: refresh, ExpiresIn: expiresIn, IssuedAt: issuedAt, Valid: true}
	if err := db.insertTokens(t); err != nil {
		return nil, errors.New("DB internal error: " + err.Error())
	}
	fmt.Println("Welcome", user.FirstName, user.LastName)
	tokensMap = make(map[string]string)
	tokensMap["accsess"] = accsess
	tokensMap["refresh"] = base64.StdEncoding.EncodeToString(refresh)
	return
}

func Refresh(oldToken string) (map[string]string, error) {
	return db.refreshToken(oldToken)
}
