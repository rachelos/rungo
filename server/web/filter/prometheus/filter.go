// Copyright 2020 rungo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prometheus

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	rungo "github.com/rachelos/rungo"
	"github.com/rachelos/rungo/core/logs"
	"github.com/rachelos/rungo/server/web"
	"github.com/rachelos/rungo/server/web/context"
)

const unknownRouterPattern = "UnknownRouterPattern"

// FilterChainBuilder is an extension point,
// when we want to support some configuration,
// please use this structure
type FilterChainBuilder struct{}

var (
	summaryVec     prometheus.ObserverVec
	initSummaryVec sync.Once
)

// FilterChain returns a FilterFunc. The filter will records some metrics
func (builder *FilterChainBuilder) FilterChain(next web.FilterFunc) web.FilterFunc {
	initSummaryVec.Do(func() {
		summaryVec = builder.buildVec()
		err := prometheus.Register(summaryVec)
		if _, ok := err.(*prometheus.AlreadyRegisteredError); err != nil && !ok {
			logs.Error("web module register prometheus vector failed, %+v", err)
		}
		registerBuildInfo()
	})

	return func(ctx *context.Context) {
		startTime := time.Now()
		next(ctx)
		endTime := time.Now()
		go report(endTime.Sub(startTime), ctx, summaryVec)
	}
}

func (builder *FilterChainBuilder) buildVec() *prometheus.SummaryVec {
	summaryVec := prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name:      "rungo",
		Subsystem: "http_request",
		ConstLabels: map[string]string{
			"server":  web.BConfig.ServerName,
			"env":     web.BConfig.RunMode,
			"appname": web.BConfig.AppName,
		},
		Help: "The statics info for http request",
	}, []string{"pattern", "method", "status"})
	return summaryVec
}

func registerBuildInfo() {
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "rungo",
		Subsystem: "build_info",
		Help:      "The building information",
		ConstLabels: map[string]string{
			"appname":        web.BConfig.AppName,
			"build_version":  rungo.BuildVersion,
			"build_revision": rungo.BuildGitRevision,
			"build_status":   rungo.BuildStatus,
			"build_tag":      rungo.BuildTag,
			"build_time":     strings.Replace(rungo.BuildTime, "--", " ", 1),
			"go_version":     rungo.GoVersion,
			"git_branch":     rungo.GitBranch,
			"start_time":     time.Now().Format("2006-01-02 15:04:05"),
		},
	}, []string{})

	_ = prometheus.Register(buildInfo)
	buildInfo.WithLabelValues().Set(1)
}

func report(dur time.Duration, ctx *context.Context, vec prometheus.ObserverVec) {
	status := ctx.Output.Status
	ptnItf := ctx.Input.GetData("RouterPattern")
	ptn := unknownRouterPattern
	if ptnItf != nil {
		ptn = ptnItf.(string)
	}
	ms := dur / time.Millisecond
	vec.WithLabelValues(ptn, ctx.Input.Method(), strconv.Itoa(status)).Observe(float64(ms))
}
