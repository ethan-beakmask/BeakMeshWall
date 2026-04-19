//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func initPlatform() {}

func waitForShutdown(moduleCount, pollInterval int) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("INFO: received %v, shutting down", s)
}
