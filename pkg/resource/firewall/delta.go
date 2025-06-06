// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

// Code generated by ack-generate. DO NOT EDIT.

package firewall

import (
	"bytes"
	"reflect"

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	acktags "github.com/aws-controllers-k8s/runtime/pkg/tags"
)

// Hack to avoid import errors during build...
var (
	_ = &bytes.Buffer{}
	_ = &reflect.Method{}
	_ = &acktags.Tags{}
)

// newResourceDelta returns a new `ackcompare.Delta` used to compare two
// resources
func newResourceDelta(
	a *resource,
	b *resource,
) *ackcompare.Delta {
	delta := ackcompare.NewDelta()
	if (a == nil && b != nil) ||
		(a != nil && b == nil) {
		delta.Add("", a, b)
		return delta
	}
	customPreCompare(delta, a, b)

	if ackcompare.HasNilDifference(a.ko.Spec.DeleteProtection, b.ko.Spec.DeleteProtection) {
		delta.Add("Spec.DeleteProtection", a.ko.Spec.DeleteProtection, b.ko.Spec.DeleteProtection)
	} else if a.ko.Spec.DeleteProtection != nil && b.ko.Spec.DeleteProtection != nil {
		if *a.ko.Spec.DeleteProtection != *b.ko.Spec.DeleteProtection {
			delta.Add("Spec.DeleteProtection", a.ko.Spec.DeleteProtection, b.ko.Spec.DeleteProtection)
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.Description, b.ko.Spec.Description) {
		delta.Add("Spec.Description", a.ko.Spec.Description, b.ko.Spec.Description)
	} else if a.ko.Spec.Description != nil && b.ko.Spec.Description != nil {
		if *a.ko.Spec.Description != *b.ko.Spec.Description {
			delta.Add("Spec.Description", a.ko.Spec.Description, b.ko.Spec.Description)
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.EncryptionConfiguration, b.ko.Spec.EncryptionConfiguration) {
		delta.Add("Spec.EncryptionConfiguration", a.ko.Spec.EncryptionConfiguration, b.ko.Spec.EncryptionConfiguration)
	} else if a.ko.Spec.EncryptionConfiguration != nil && b.ko.Spec.EncryptionConfiguration != nil {
		if ackcompare.HasNilDifference(a.ko.Spec.EncryptionConfiguration.KeyID, b.ko.Spec.EncryptionConfiguration.KeyID) {
			delta.Add("Spec.EncryptionConfiguration.KeyID", a.ko.Spec.EncryptionConfiguration.KeyID, b.ko.Spec.EncryptionConfiguration.KeyID)
		} else if a.ko.Spec.EncryptionConfiguration.KeyID != nil && b.ko.Spec.EncryptionConfiguration.KeyID != nil {
			if *a.ko.Spec.EncryptionConfiguration.KeyID != *b.ko.Spec.EncryptionConfiguration.KeyID {
				delta.Add("Spec.EncryptionConfiguration.KeyID", a.ko.Spec.EncryptionConfiguration.KeyID, b.ko.Spec.EncryptionConfiguration.KeyID)
			}
		}
		if ackcompare.HasNilDifference(a.ko.Spec.EncryptionConfiguration.Type, b.ko.Spec.EncryptionConfiguration.Type) {
			delta.Add("Spec.EncryptionConfiguration.Type", a.ko.Spec.EncryptionConfiguration.Type, b.ko.Spec.EncryptionConfiguration.Type)
		} else if a.ko.Spec.EncryptionConfiguration.Type != nil && b.ko.Spec.EncryptionConfiguration.Type != nil {
			if *a.ko.Spec.EncryptionConfiguration.Type != *b.ko.Spec.EncryptionConfiguration.Type {
				delta.Add("Spec.EncryptionConfiguration.Type", a.ko.Spec.EncryptionConfiguration.Type, b.ko.Spec.EncryptionConfiguration.Type)
			}
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.FirewallName, b.ko.Spec.FirewallName) {
		delta.Add("Spec.FirewallName", a.ko.Spec.FirewallName, b.ko.Spec.FirewallName)
	} else if a.ko.Spec.FirewallName != nil && b.ko.Spec.FirewallName != nil {
		if *a.ko.Spec.FirewallName != *b.ko.Spec.FirewallName {
			delta.Add("Spec.FirewallName", a.ko.Spec.FirewallName, b.ko.Spec.FirewallName)
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.FirewallPolicyARN, b.ko.Spec.FirewallPolicyARN) {
		delta.Add("Spec.FirewallPolicyARN", a.ko.Spec.FirewallPolicyARN, b.ko.Spec.FirewallPolicyARN)
	} else if a.ko.Spec.FirewallPolicyARN != nil && b.ko.Spec.FirewallPolicyARN != nil {
		if *a.ko.Spec.FirewallPolicyARN != *b.ko.Spec.FirewallPolicyARN {
			delta.Add("Spec.FirewallPolicyARN", a.ko.Spec.FirewallPolicyARN, b.ko.Spec.FirewallPolicyARN)
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.FirewallPolicyChangeProtection, b.ko.Spec.FirewallPolicyChangeProtection) {
		delta.Add("Spec.FirewallPolicyChangeProtection", a.ko.Spec.FirewallPolicyChangeProtection, b.ko.Spec.FirewallPolicyChangeProtection)
	} else if a.ko.Spec.FirewallPolicyChangeProtection != nil && b.ko.Spec.FirewallPolicyChangeProtection != nil {
		if *a.ko.Spec.FirewallPolicyChangeProtection != *b.ko.Spec.FirewallPolicyChangeProtection {
			delta.Add("Spec.FirewallPolicyChangeProtection", a.ko.Spec.FirewallPolicyChangeProtection, b.ko.Spec.FirewallPolicyChangeProtection)
		}
	}
	if ackcompare.HasNilDifference(a.ko.Spec.SubnetChangeProtection, b.ko.Spec.SubnetChangeProtection) {
		delta.Add("Spec.SubnetChangeProtection", a.ko.Spec.SubnetChangeProtection, b.ko.Spec.SubnetChangeProtection)
	} else if a.ko.Spec.SubnetChangeProtection != nil && b.ko.Spec.SubnetChangeProtection != nil {
		if *a.ko.Spec.SubnetChangeProtection != *b.ko.Spec.SubnetChangeProtection {
			delta.Add("Spec.SubnetChangeProtection", a.ko.Spec.SubnetChangeProtection, b.ko.Spec.SubnetChangeProtection)
		}
	}
	desiredACKTags, _ := convertToOrderedACKTags(a.ko.Spec.Tags)
	latestACKTags, _ := convertToOrderedACKTags(b.ko.Spec.Tags)
	if !ackcompare.MapStringStringEqual(desiredACKTags, latestACKTags) {
		delta.Add("Spec.Tags", a.ko.Spec.Tags, b.ko.Spec.Tags)
	}
	if ackcompare.HasNilDifference(a.ko.Spec.VPCID, b.ko.Spec.VPCID) {
		delta.Add("Spec.VPCID", a.ko.Spec.VPCID, b.ko.Spec.VPCID)
	} else if a.ko.Spec.VPCID != nil && b.ko.Spec.VPCID != nil {
		if *a.ko.Spec.VPCID != *b.ko.Spec.VPCID {
			delta.Add("Spec.VPCID", a.ko.Spec.VPCID, b.ko.Spec.VPCID)
		}
	}

	return delta
}
