package dbl

import (
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"golang.org/x/crypto/bcrypt"
)

type tokens struct {
	GUID      primitive.ObjectID `bson:"guid,omitempty"`
	AccessTk  string             `bson:"accsess,omitempty"`
	RefreshTk []byte             `bson:"refresh,omitempty"`
	Valid     bool               `bson:"valid,omitempty"`
	IssuedAt  int64              `bson:"issuedAt,omitempty"`
	ExpiresIn int64              `bson:"expiresIn,omitempty"`
}

func makeRefreshToken() ([]byte, error) {
	var str string
	bytes, err := bcrypt.GenerateFromPassword([]byte(str), bcrypt.DefaultCost)
	return bytes, err
}

func makeAccsessToken(claims customClaims) (jwtToken string, err error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS512"), claims)
	jwtToken, err = token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", err
	}
	return jwtToken, nil
}

func (db *DBlayer) insertTokens(t tokens) (err error) {
	wcMajority := writeconcern.New(writeconcern.WMajority(), writeconcern.WTimeout(1*time.Second))
	wcMajorityCollectionOpts := options.Collection().SetWriteConcern(wcMajority)
	coll := db.client.Database("test").Collection("tokens", wcMajorityCollectionOpts)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		if _, err := coll.InsertOne(sessCtx, t); err != nil {
			return nil, err
		}
		return nil, nil
	}

	session, err := db.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(db.ctx)

	_, err = session.WithTransaction(db.ctx, callback)
	if err != nil {
		return err
	}
	return

}

func (db *DBlayer) refreshToken(oldToken string) (tokensMap map[string]string, err error) {
	ok, err := db.tokenIsExpired(oldToken)
	if err == mongo.ErrNoDocuments {
		return nil, errors.New("No such token")
	}
	if err != nil {
		return nil, err
	}

	if ok {
		return nil, errors.New("refresh token is expired. You need to re-login")
	}
	ok, err = db.tokenIsValid(oldToken)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("refresh token is invalid. You need to re-login")
	}
	if err := db.makeOldTokenInvalid(oldToken); err != nil {
		return nil, err
	}
	guid, err := db.getGUIDbyToken(oldToken)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	issuedAt := now.Unix()
	expiresIn := now.Add(time.Second * time.Duration(db.p.accessTTL)).Unix()
	claims := customClaims{
		guid.String(),
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
	t := tokens{GUID: guid, AccessTk: accsess, RefreshTk: refresh, ExpiresIn: expiresIn, IssuedAt: issuedAt, Valid: true}
	if err := db.insertTokens(t); err != nil {
		return nil, errors.New("DB internal error: " + err.Error())
	}
	tokensMap = make(map[string]string)
	tokensMap["accsess"] = accsess
	tokensMap["refresh"] = base64.StdEncoding.EncodeToString(refresh)
	return

}

func (db *DBlayer) makeOldTokenInvalid(oldToken string) (err error) {
	wcMajority := writeconcern.New(writeconcern.WMajority(), writeconcern.WTimeout(1*time.Second))
	wcMajorityCollectionOpts := options.Collection().SetWriteConcern(wcMajority)
	coll := db.client.Database("test").Collection("tokens", wcMajorityCollectionOpts)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		if _, err := coll.UpdateOne(sessCtx,
			bson.M{"refresh": primitive.Binary{Data: []byte(oldToken), Subtype: 0}},
			bson.D{
				{"$set", bson.D{{"valid", false}}},
			},
		); err != nil {
			return nil, err
		}
		return nil, nil
	}

	session, err := db.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(db.ctx)

	_, err = session.WithTransaction(db.ctx, callback)
	if err != nil {
		return err
	}
	return
}

func (db *DBlayer) tokenIsExpired(token string) (ok bool, err error) {
	coll := db.client.Database("test").Collection("tokens")
	var t tokens
	//TODO Must use transaction
	err = coll.FindOne(db.ctx, bson.M{"refresh": primitive.Binary{Data: []byte(token), Subtype: 0}}).Decode(&t)
	if err == mongo.ErrNoDocuments {
		return false, err
	}
	if err != nil && err != mongo.ErrNoDocuments {
		return false, err
	}
	if time.Now().Unix() > t.ExpiresIn {
		return true, err
	}
	return
}

func (db *DBlayer) getGUIDbyToken(token string) (guid primitive.ObjectID, err error) {
	coll := db.client.Database("test").Collection("tokens")
	var t tokens
	//TODO Must use transaction
	err = coll.FindOne(db.ctx, bson.M{"refresh": primitive.Binary{Data: []byte(token), Subtype: 0}}).Decode(&t)
	if err == mongo.ErrNoDocuments {
		return guid, err
	}
	if err != nil && err != mongo.ErrNoDocuments {
		return guid, err
	}
	guid = t.GUID
	return
}

func (db *DBlayer) tokenIsValid(token string) (ok bool, err error) {
	coll := db.client.Database("test").Collection("tokens")
	var t tokens
	//TODO Must use transaction
	err = coll.FindOne(db.ctx, bson.M{"refresh": primitive.Binary{Data: []byte(token), Subtype: 0}}).Decode(&t)
	if err == mongo.ErrNoDocuments {
		return ok, err
	}
	if err != nil && err != mongo.ErrNoDocuments {
		return ok, err
	}
	ok = t.Valid
	return
}

func (db *DBlayer) deleteToken(token string) (err error) {
	_, err = db.tokenIsValid(token)
	if err == mongo.ErrNoDocuments {
		return errors.New("No such token")
	}
	if err != nil {
		return err
	}
	wcMajority := writeconcern.New(writeconcern.WMajority(), writeconcern.WTimeout(1*time.Second))
	wcMajorityCollectionOpts := options.Collection().SetWriteConcern(wcMajority)
	coll := db.client.Database("test").Collection("tokens", wcMajorityCollectionOpts)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		if _, err := coll.DeleteOne(sessCtx, bson.M{"refresh": primitive.Binary{Data: []byte(token), Subtype: 0}}); err != nil {
			return nil, err
		}
		return nil, nil
	}

	session, err := db.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(db.ctx)

	_, err = session.WithTransaction(db.ctx, callback)
	if err != nil {
		return err
	}
	return
}

func (db *DBlayer) deleteTokensWithGUID(guid string) (err error) {
	id, err := primitive.ObjectIDFromHex(guid)
	if err != nil {
		return errors.New("Check that GUID correspond to ObjectID. See https://docs.mongodb.com/manual/reference/bson-types/#objectid")
	}

	ok, err := db.userExist(id)
	if err != nil {
		return errors.New("Error occured on the server-side: " + err.Error() + " Repeat again later")
	}
	if !ok {
		return errors.New("GUID incorrect. Try again")
	}

	wcMajority := writeconcern.New(writeconcern.WMajority(), writeconcern.WTimeout(1*time.Second))
	wcMajorityCollectionOpts := options.Collection().SetWriteConcern(wcMajority)
	coll := db.client.Database("test").Collection("tokens", wcMajorityCollectionOpts)
	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		if _, err := coll.DeleteMany(sessCtx, bson.M{"guid": id}); err != nil {
			return nil, err
		}
		return nil, nil
	}

	session, err := db.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(db.ctx)

	_, err = session.WithTransaction(db.ctx, callback)
	if err != nil {
		return err
	}
	return
}

func DeleteToken(token string) error {
	return db.deleteToken(token)
}

func DeleteAllTokens(guid string) error {
	return db.deleteTokensWithGUID(guid)
}
