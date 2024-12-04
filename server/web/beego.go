// Copyright 2014 rungo Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"os"
	"path/filepath"
	"sync"
)

const (
	// DEV is for develop
	DEV = "dev"
	// PROD is for production
	PROD = "prod"
)

// M is Map shortcut
type M map[string]interface{}

// Hook function to run
type hookfunc func() error

var hooks = make([]hookfunc, 0) // hook function slice to store the hookfunc

// AddAPPStartHook is used to register the hookfunc
// The hookfuncs will run in rungo.Run()
// such as initiating session , starting middleware , building template, starting admin control and so on.
func AddAPPStartHook(hf ...hookfunc) {
	hooks = append(hooks, hf...)
}

// Run rungo application.
// rungo.Run() default run on HttpPort
// rungo.Run("localhost")
// rungo.Run(":8089")
// rungo.Run("127.0.0.1:8089")
func Run(params ...string) {
	if len(params) > 0 && params[0] != "" {
		RunApp.Run(params[0])
	} else {
		RunApp.Run("")
	}
}

// RunWithMiddleWares Run rungo application with middlewares.
func RunWithMiddleWares(addr string, mws ...MiddleWare) {
	RunApp.Run(addr, mws...)
}

var initHttpOnce sync.Once

// TODO move to module init function
func initBeforeHTTPRun() {
	initHttpOnce.Do(func() {
		// init hooks
		AddAPPStartHook(
			registerMime,
			registerDefaultErrorHandler,
			registerSession,
			registerTemplate,
			registerAdmin,
			registerGzip,
			// registerCommentRouter,
		)

		for _, hk := range hooks {
			if err := hk(); err != nil {
				panic(err)
			}
		}
	})
}

// TestrungoInit is for test package init
func TestrungoInit(ap string) {
	path := filepath.Join(ap, "conf", "app.conf")
	os.Chdir(ap)
	InitrungoBeforeTest(path)
}

// InitrungoBeforeTest is for test package init
func InitrungoBeforeTest(appConfigPath string) {
	if err := LoadAppConfig(appConfigProvider, appConfigPath); err != nil {
		panic(err)
	}
	BConfig.RunMode = "test"
	initBeforeHTTPRun()
}
