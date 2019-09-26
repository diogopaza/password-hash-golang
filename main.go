package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type User struct {
	Username string `json:username`
	Password string `json:password`
}

const (
	host           = "localhost"
	port           = 5432
	user           = "postgres"
	password_admin = "123321"
	dbname         = "login"
)

func main() {

	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/signup", Signup)

	initDB()

	log.Fatal(http.ListenAndServe(":8000", nil))

}

func Signin(w http.ResponseWriter, r *http.Request) {
	user := User{}
	DBuser := User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fmt.Println("usuario ", user.Username)
	row := db.QueryRow("SELECT * FROM users WHERE username=$1", user.Username)
	err = row.Scan(&DBuser.Username, &DBuser.Password)
	if err != nil {
		fmt.Println("Usuário não cadastrado")
		w.WriteHeader(401)
		return
	}
	if err == sql.ErrNoRows {
		fmt.Println("Usuario não encontrado")
		w.WriteHeader(401)
		return
	}
	_ = row
	fmt.Println(DBuser.Password)
	fmt.Println(user.Password)
	if err = bcrypt.CompareHashAndPassword([]byte(DBuser.Password), []byte(user.Password)); err != nil {
		fmt.Println("erro de hash")
		w.WriteHeader((http.StatusUnauthorized))
		return
	}
	json.NewEncoder(w).Encode("Usuário autenticado")
	return
}

func Signup(w http.ResponseWriter, r *http.Request) {
	fmt.Println("entrei")
	user := User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	//dataAtual := time.Now()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 16)
	fmt.Println(user)
	sqlQuery := `INSERT INTO users("username","password") VALUES($1,$2)`
	row, err := db.Exec(sqlQuery, user.Username, hashedPassword)
	if err != nil {
		fmt.Println("Erro ao cadastrar no banco ", err)
		return
	}
	_ = row
	json.NewEncoder(w).Encode("Usuario cadastrado com sucesso")
	return
}

func initDB() {
	var err error
	banco := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password_admin, dbname)
	db, err = sql.Open("postgres", banco)
	if err != nil {
		fmt.Println("Erro ao conectar banco")
		panic(err)
	}
	err = db.Ping()

}
