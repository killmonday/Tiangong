package main

import (
	"testing"
)

func TestQuser(t *testing.T) {
	username := quser()
	t.Log("username:", username)
}
