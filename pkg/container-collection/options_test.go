// Copyright 2019-2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package containercollection

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetExpectedOwnerReference(t *testing.T) {
	cTrue := true
	cFalse := false
	table := []struct {
		description     string
		ownerReferences []metav1.OwnerReference
		expectedResult  *metav1.OwnerReference
	}{
		{
			description:     "From empty list",
			ownerReferences: []metav1.OwnerReference{},
		},
		{
			description: "Neither controller reference nor expected kind",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
			},
		},
		{
			description: "One element with expected kind",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde",
					Kind:       "Deployment",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde",
			},
		},
		{
			description: "Selecting first expected kind reference (First element)",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "ReplicaSet",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "StatefulSet",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "DaemonSet",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde1",
			},
		},
		{
			description: "Selecting first expected kind reference (Intermediate element)",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "Job",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "CronJob",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde2",
			},
		},
		{
			description: "Selecting first expected kind reference (Last element)",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "ReplicationController",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde3",
			},
		},
		{
			description: "Nil controller flag",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:  "abcde",
					Kind: "CronJob",
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde",
			},
		},
		{
			description: "Controller reference without expected kind and no fallback",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cTrue,
				},
				{
					UID:        "abcde2",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "non-expected-kind",
					Controller: &cFalse,
				},
			},
		},
		{
			description: "Fallback references for controller reference without expected kind",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "non-expected-kind",
					Controller: &cTrue,
				},
				{
					UID:        "abcde2",
					Kind:       "ReplicaSet",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "StatefulSet",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde2",
			},
		},
		{
			description: "Selecting controller reference (First element)",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "Deployment",
					Controller: &cTrue,
				},
				{
					UID:        "abcde2",
					Kind:       "Job",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "ReplicaSet",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde1",
			},
		},
		{
			description: "Selecting controller reference (Intermediate element)",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "DaemonSet",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "ReplicationController",
					Controller: &cTrue,
				},
				{
					UID:        "abcde3",
					Kind:       "StatefulSet",
					Controller: &cFalse,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde2",
			},
		},
		{
			description: "Selecting controller reference (Last element)",
			ownerReferences: []metav1.OwnerReference{
				{
					UID:        "abcde1",
					Kind:       "ReplicaSet",
					Controller: &cFalse,
				},
				{
					UID:        "abcde2",
					Kind:       "Deployment",
					Controller: &cFalse,
				},
				{
					UID:        "abcde3",
					Kind:       "CronJob",
					Controller: &cTrue,
				},
			},
			expectedResult: &metav1.OwnerReference{
				UID: "abcde3",
			},
		},
	}

	for i, entry := range table {
		result := getExpectedOwnerReference(entry.ownerReferences)
		if entry.expectedResult == nil {
			require.Nil(t, result, "Failed test %q (index %d): result %+v expected %+v",
				entry.description, i, result, entry.expectedResult)
		} else {
			require.NotNil(t, result, "Failed test %q (index %d): result %+v expected %+v",
				entry.description, i, result, entry.expectedResult)
			require.Equal(t, entry.expectedResult.UID, result.UID, "Failed test %q (index %d): result %+v expected %+v",
				entry.description, i, result, entry.expectedResult)
		}
	}
}

// ociConfigEnricher builds a ContainerCollection with only WithOCIConfigEnrichment
// installed and returns its single enricher function directly, so tests can
// exercise the enricher's decision logic without going through AddContainer's
// dedup/publish machinery.
func ociConfigEnricher(t *testing.T) func(*Container) bool {
	t.Helper()
	cc := &ContainerCollection{}
	require.NoError(t, WithOCIConfigEnrichment()(cc))
	require.Len(t, cc.containerEnrichers, 1)
	return cc.containerEnrichers[0]
}

const containerdSandboxOciConfig = `{"annotations":{"io.kubernetes.cri.container-type":"sandbox"}}`

// TestOCIConfigEnrichmentDropsHookSuppliedSandbox is a regression guard for
// the pre-existing pod-sandbox drop: a container whose OciConfig was already
// populated when it reached this enricher (the WithContainerFanotifyEbpf
// shape, which captures config.json directly at container-create time and so
// can assert "this really is a sandbox" with certainty) must still be
// dropped. The R3 change (deriving OciConfig for containers that arrive
// without one) must not weaken this case.
func TestOCIConfigEnrichmentDropsHookSuppliedSandbox(t *testing.T) {
	enrich := ociConfigEnricher(t)
	container := &Container{OciConfig: containerdSandboxOciConfig}

	require.False(t, enrich(container), "a hook-supplied sandbox config must still be dropped")
}

// TestOCIConfigEnrichmentDoesNotDropOnFailedDerivation is the counterpart:
// a container that reaches this enricher WITHOUT an OciConfig (e.g. from
// WithContainerRuntimeEnrichment's CRI-based discovery, which never sets
// one) and whose derivation fails (no real process/bundle to introspect, the
// ordinary case in a unit test) must be kept, not dropped -- derivation
// failure is "stays unenriched", never "vanishes from the collection".
func TestOCIConfigEnrichmentDoesNotDropOnFailedDerivation(t *testing.T) {
	enrich := ociConfigEnricher(t)
	container := &Container{}
	container.Runtime.ContainerPID = 0 // unresolvable: deriveOciConfig must fail closed, not panic

	require.True(t, enrich(container), "derivation failure must not drop the container")
	require.Empty(t, container.OciConfig, "a failed derivation must leave OciConfig empty, not partially populated")
}
