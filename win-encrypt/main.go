package main

import (
	"fmt"
	"log"
	"os"
	"win-encrypt/internal/gui"
)

func main() {
	// Konfiguracja logowania
	f, err := os.OpenFile("debug.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Błąd otwierania pliku logów: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	log.SetOutput(f)

	log.Println("Uruchamianie aplikacji...")

	// Uruchomienie GUI
	err = gui.RunApp()
	if err != nil {
		log.Printf("Błąd podczas uruchamiania aplikacji: %v\n", err)
		fmt.Printf("Błąd podczas uruchamiania aplikacji: %v\n", err)
		os.Exit(1)
	}
}
