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

package firewall

import (
	"context"
	"errors"
	"sort"

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	svcsdk "github.com/aws/aws-sdk-go/service/networkfirewall"
)

var (
	requeueWaitWhileDeleting = ackrequeue.NeededAfter(
		errors.New(GroupKind.Kind+" is deleting."),
		ackrequeue.DefaultRequeueAfterDuration,
	)
)

func (rm *resourceManager) customUpdateFirewall(
	ctx context.Context,
	desired *resource,
	latest *resource,
	delta *ackcompare.Delta,
) (updated *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.customUpdateFirewall")
	defer exit(err)

	ko := desired.ko.DeepCopy()

	rm.setStatusDefaults(ko)

	if delta.DifferentAt("Spec.FirewallPolicyARN") {
		if err = rm.syncFirewallPolicyARN(ctx, desired, latest); err != nil {
			return nil, err
		}
	}

	ko.Status.Firewall.FirewallPolicyARN = desired.ko.Spec.FirewallPolicyARN

	return &resource{ko}, nil
}

func (rm *resourceManager) syncFirewallPolicyARN(
	ctx context.Context,
	desired *resource,
	latest *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.syncFirewallPolicyARN")
	defer exit(err)

	input := &svcsdk.AssociateFirewallPolicyInput{}

	// Fetch latest firewall information from AWS.
	if latest.ko.Status.Firewall != nil && latest.ko.Status.Firewall.FirewallARN != nil {
		input.FirewallArn = latest.ko.Status.Firewall.FirewallARN
	}

	// Update firewall policy ARN with desired value.
	if desired.ko.Spec.FirewallPolicyARN != nil {
		input.FirewallPolicyArn = desired.ko.Spec.FirewallPolicyARN
	}

	_, err = rm.sdkapi.AssociateFirewallPolicyWithContext(ctx, input)
	rm.metrics.RecordAPICall("UPDATE", "AssociateFirewallPolicy", err)
	if err != nil {
		return err
	}

	return nil
}

func customPreCompare(
	a *resource,
	b *resource,
) {
	// Sort subnet mappings such that they can be compared in a deterministic way.
	customPreCompareSubnetMappings(a, b)
}

func customPreCompareSubnetMappings(
	a *resource,
	b *resource,
) {
	if a.ko.Spec.SubnetMappings != nil {
		sort.Slice(a.ko.Spec.SubnetMappings[:], func(i, j int) bool {
			return *a.ko.Spec.SubnetMappings[i].SubnetID < *a.ko.Spec.SubnetMappings[j].SubnetID
		})
	}
	if b.ko.Spec.SubnetMappings != nil {
		sort.Slice(b.ko.Spec.SubnetMappings[:], func(i, j int) bool {
			return *b.ko.Spec.SubnetMappings[i].SubnetID < *b.ko.Spec.SubnetMappings[j].SubnetID
		})
	}
}
