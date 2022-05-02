// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package policy

import (
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type PolicyTestSuite struct{}

var _ = Suite(&PolicyTestSuite{})

func BenchmarkSearchContextString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, sc := range []SearchContext{
			{
				Trace: 1,
				Depth: 0,
				From:  labels.ParseLabelArray("a", "c", "b"),
				To:    labels.ParseLabelArray("d", "e", "f"),
				DPorts: []*models.Port{
					{
						Name:     "HTTP",
						Port:     80,
						Protocol: "TCP",
					},
					{
						Name:     "HTTPs",
						Port:     442,
						Protocol: "TCP",
					},
				},
				rulesSelect: false,
			},
			{
				Trace: 1,
				Depth: 0,
				From:  labels.ParseLabelArray("a", "c", "b"),
				To:    labels.ParseLabelArray("d", "e", "f"),
				DPorts: []*models.Port{
					{
						Port:     80,
						Protocol: "TCP",
					},
					{
						Port:     442,
						Protocol: "TCP",
					},
				},
				rulesSelect: false,
			},
		} {
			_ = sc.String()
		}
	}
}
