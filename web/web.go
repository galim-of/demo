package web

import (
	"demo/dbl"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

type user struct {
	GUID      string `json:"guid"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type response struct {
	Accsess string `json:"accsess"`
	Refresh string `json:"refresh"`
}

type RefreshTkn struct {
	Refresh string `json:"refresh"`
}

func Authenticate(w http.ResponseWriter, req *http.Request) {
	var (
		u      user
		r      response
		tokens map[string]string
		err    error
	)

	if err = json.NewDecoder(req.Body).Decode(&u); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Get: %s\nWait:\n{\n\t\"guid\": <ObjectID>\n\t\"password\": <secret>\n}\n", err)
		return
	}
	if tokens, err = dbl.AuthenticateUser(u.GUID, u.Password); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "%s\n", err)
		return
	}

	r.Accsess = tokens["accsess"]
	r.Refresh = tokens["refresh"]
	if err = json.NewEncoder(w).Encode(r); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s\n", err)
		return
	}

}

func Register(w http.ResponseWriter, req *http.Request) {
	var (
		u   user
		id  string
		err error
	)
	if err = json.NewDecoder(req.Body).Decode(&u); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Get: %s\nWait:\n{\n\t\"firstName\": <string>\n\t\"lastName\": <string>\n\t\"password\": <secret>\n}\n", err)
		return
	}

	if id, err = dbl.RegisterUser(u.FirstName, u.LastName, u.Password); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "%s\n", err)
		return
	}
	fmt.Fprintf(w, "%s\n", id)

}

func Refresh(w http.ResponseWriter, req *http.Request) {
	var (
		r      RefreshTkn
		resp   response
		tokens map[string]string
		err    error
	)
	if err = json.NewDecoder(req.Body).Decode(&r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Get: %s\nWait:\n{\n\t\"refresh\": <base64>\n}\n", err)
		return
	}

	base64Token, err := base64.StdEncoding.DecodeString(r.Refresh)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Check that refresh token is in base64 format: %s\n", err)
		return
	}

	if tokens, err = dbl.Refresh(string(base64Token)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "%s\n", err)
		return
	}

	resp.Accsess = tokens["accsess"]
	resp.Refresh = tokens["refresh"]
	if err = json.NewEncoder(w).Encode(resp); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s\n", err)
		return
	}
}

func Delete(w http.ResponseWriter, req *http.Request) {
	var (
		r   RefreshTkn
		err error
	)
	if err = json.NewDecoder(req.Body).Decode(&r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Get: %s\nWait:\n{\n\t\"refresh\": <base64>\n}\n", err)
		return
	}

	base64Token, err := base64.StdEncoding.DecodeString(r.Refresh)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Check that refresh token is in base64 format: %s\n", err)
		return
	}
	if err := dbl.DeleteToken(string(base64Token)); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s\n", err)
		return
	}
	fmt.Fprintf(w, "ok\n")
}

func DeleteAll(w http.ResponseWriter, req *http.Request) {
	var (
		u   user
		err error
	)
	if err = json.NewDecoder(req.Body).Decode(&u); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Get: %s\nWait:\n{\n\t\"guid\": <ObjectID>\n}\n", err)
		return
	}

	if err := dbl.DeleteAllTokens(u.GUID); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s\n", err)
		return
	}
	fmt.Fprintf(w, "ok\n")

}
