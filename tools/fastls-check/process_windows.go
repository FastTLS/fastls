package main

import (
	"os/exec"
	"strconv"
	"time"
)

func configureProcess(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return exec.Command("taskkill", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run() }
	cmd.WaitDelay = 2 * time.Second
}
