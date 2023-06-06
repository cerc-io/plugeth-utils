// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

//go:build !gofuzz && cgo && linkgeth
// +build !gofuzz,cgo,linkgeth

// Package secp256k1 wraps the bitcoin secp256k1 C library.
package secp256k1

/*
#cgo CFLAGS: -DPLUGETH_LINK_GETH
*/
import "C"
