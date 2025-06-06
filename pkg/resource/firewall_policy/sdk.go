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

package firewall_policy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"

	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackcondition "github.com/aws-controllers-k8s/runtime/pkg/condition"
	ackerr "github.com/aws-controllers-k8s/runtime/pkg/errors"
	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	smithy "github.com/aws/smithy-go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	svcapitypes "github.com/aws-controllers-k8s/networkfirewall-controller/apis/v1alpha1"
)

// Hack to avoid import errors during build...
var (
	_ = &metav1.Time{}
	_ = strings.ToLower("")
	_ = &svcsdk.Client{}
	_ = &svcapitypes.FirewallPolicy{}
	_ = ackv1alpha1.AWSAccountID("")
	_ = &ackerr.NotFound
	_ = &ackcondition.NotManagedMessage
	_ = &reflect.Value{}
	_ = fmt.Sprintf("")
	_ = &ackrequeue.NoRequeue{}
	_ = &aws.Config{}
)

// sdkFind returns SDK-specific information about a supplied resource
func (rm *resourceManager) sdkFind(
	ctx context.Context,
	r *resource,
) (latest *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.sdkFind")
	defer func() {
		exit(err)
	}()
	// If any required fields in the input shape are missing, AWS resource is
	// not created yet. Return NotFound here to indicate to callers that the
	// resource isn't yet created.
	if rm.requiredFieldsMissingFromReadOneInput(r) {
		return nil, ackerr.NotFound
	}

	input, err := rm.newDescribeRequestPayload(r)
	if err != nil {
		return nil, err
	}

	var resp *svcsdk.DescribeFirewallPolicyOutput
	resp, err = rm.sdkapi.DescribeFirewallPolicy(ctx, input)
	rm.metrics.RecordAPICall("READ_ONE", "DescribeFirewallPolicy", err)
	if err != nil {
		var awsErr smithy.APIError
		if errors.As(err, &awsErr) && awsErr.ErrorCode() == "ResourceNotFoundException" {
			return nil, ackerr.NotFound
		}
		return nil, err
	}

	// Merge in the information we read from the API call above to the copy of
	// the original Kubernetes object we passed to the function
	ko := r.ko.DeepCopy()

	if resp.FirewallPolicy != nil {
		f0 := &svcapitypes.FirewallPolicy_SDK{}
		if resp.FirewallPolicy.PolicyVariables != nil {
			f0f0 := &svcapitypes.PolicyVariables{}
			if resp.FirewallPolicy.PolicyVariables.RuleVariables != nil {
				f0f0f0 := map[string]*svcapitypes.IPSet{}
				for f0f0f0key, f0f0f0valiter := range resp.FirewallPolicy.PolicyVariables.RuleVariables {
					f0f0f0val := &svcapitypes.IPSet{}
					if f0f0f0valiter.Definition != nil {
						f0f0f0val.Definition = aws.StringSlice(f0f0f0valiter.Definition)
					}
					f0f0f0[f0f0f0key] = f0f0f0val
				}
				f0f0.RuleVariables = f0f0f0
			}
			f0.PolicyVariables = f0f0
		}
		if resp.FirewallPolicy.StatefulDefaultActions != nil {
			f0.StatefulDefaultActions = aws.StringSlice(resp.FirewallPolicy.StatefulDefaultActions)
		}
		if resp.FirewallPolicy.StatefulEngineOptions != nil {
			f0f2 := &svcapitypes.StatefulEngineOptions{}
			if resp.FirewallPolicy.StatefulEngineOptions.RuleOrder != "" {
				f0f2.RuleOrder = aws.String(string(resp.FirewallPolicy.StatefulEngineOptions.RuleOrder))
			}
			if resp.FirewallPolicy.StatefulEngineOptions.StreamExceptionPolicy != "" {
				f0f2.StreamExceptionPolicy = aws.String(string(resp.FirewallPolicy.StatefulEngineOptions.StreamExceptionPolicy))
			}
			f0.StatefulEngineOptions = f0f2
		}
		if resp.FirewallPolicy.StatefulRuleGroupReferences != nil {
			f0f3 := []*svcapitypes.StatefulRuleGroupReference{}
			for _, f0f3iter := range resp.FirewallPolicy.StatefulRuleGroupReferences {
				f0f3elem := &svcapitypes.StatefulRuleGroupReference{}
				if f0f3iter.Override != nil {
					f0f3elemf0 := &svcapitypes.StatefulRuleGroupOverride{}
					if f0f3iter.Override.Action != "" {
						f0f3elemf0.Action = aws.String(string(f0f3iter.Override.Action))
					}
					f0f3elem.Override = f0f3elemf0
				}
				if f0f3iter.Priority != nil {
					priorityCopy := int64(*f0f3iter.Priority)
					f0f3elem.Priority = &priorityCopy
				}
				if f0f3iter.ResourceArn != nil {
					f0f3elem.ResourceARN = f0f3iter.ResourceArn
				}
				f0f3 = append(f0f3, f0f3elem)
			}
			f0.StatefulRuleGroupReferences = f0f3
		}
		if resp.FirewallPolicy.StatelessCustomActions != nil {
			f0f4 := []*svcapitypes.CustomAction{}
			for _, f0f4iter := range resp.FirewallPolicy.StatelessCustomActions {
				f0f4elem := &svcapitypes.CustomAction{}
				if f0f4iter.ActionDefinition != nil {
					f0f4elemf0 := &svcapitypes.ActionDefinition{}
					if f0f4iter.ActionDefinition.PublishMetricAction != nil {
						f0f4elemf0f0 := &svcapitypes.PublishMetricAction{}
						if f0f4iter.ActionDefinition.PublishMetricAction.Dimensions != nil {
							f0f4elemf0f0f0 := []*svcapitypes.Dimension{}
							for _, f0f4elemf0f0f0iter := range f0f4iter.ActionDefinition.PublishMetricAction.Dimensions {
								f0f4elemf0f0f0elem := &svcapitypes.Dimension{}
								if f0f4elemf0f0f0iter.Value != nil {
									f0f4elemf0f0f0elem.Value = f0f4elemf0f0f0iter.Value
								}
								f0f4elemf0f0f0 = append(f0f4elemf0f0f0, f0f4elemf0f0f0elem)
							}
							f0f4elemf0f0.Dimensions = f0f4elemf0f0f0
						}
						f0f4elemf0.PublishMetricAction = f0f4elemf0f0
					}
					f0f4elem.ActionDefinition = f0f4elemf0
				}
				if f0f4iter.ActionName != nil {
					f0f4elem.ActionName = f0f4iter.ActionName
				}
				f0f4 = append(f0f4, f0f4elem)
			}
			f0.StatelessCustomActions = f0f4
		}
		if resp.FirewallPolicy.StatelessDefaultActions != nil {
			f0.StatelessDefaultActions = aws.StringSlice(resp.FirewallPolicy.StatelessDefaultActions)
		}
		if resp.FirewallPolicy.StatelessFragmentDefaultActions != nil {
			f0.StatelessFragmentDefaultActions = aws.StringSlice(resp.FirewallPolicy.StatelessFragmentDefaultActions)
		}
		if resp.FirewallPolicy.StatelessRuleGroupReferences != nil {
			f0f7 := []*svcapitypes.StatelessRuleGroupReference{}
			for _, f0f7iter := range resp.FirewallPolicy.StatelessRuleGroupReferences {
				f0f7elem := &svcapitypes.StatelessRuleGroupReference{}
				if f0f7iter.Priority != nil {
					priorityCopy := int64(*f0f7iter.Priority)
					f0f7elem.Priority = &priorityCopy
				}
				if f0f7iter.ResourceArn != nil {
					f0f7elem.ResourceARN = f0f7iter.ResourceArn
				}
				f0f7 = append(f0f7, f0f7elem)
			}
			f0.StatelessRuleGroupReferences = f0f7
		}
		if resp.FirewallPolicy.TLSInspectionConfigurationArn != nil {
			f0.TLSInspectionConfigurationARN = resp.FirewallPolicy.TLSInspectionConfigurationArn
		}
		ko.Spec.FirewallPolicy = f0
	} else {
		ko.Spec.FirewallPolicy = nil
	}
	if resp.FirewallPolicyResponse != nil {
		f1 := &svcapitypes.FirewallPolicyResponse{}
		if resp.FirewallPolicyResponse.ConsumedStatefulRuleCapacity != nil {
			consumedStatefulRuleCapacityCopy := int64(*resp.FirewallPolicyResponse.ConsumedStatefulRuleCapacity)
			f1.ConsumedStatefulRuleCapacity = &consumedStatefulRuleCapacityCopy
		}
		if resp.FirewallPolicyResponse.ConsumedStatelessRuleCapacity != nil {
			consumedStatelessRuleCapacityCopy := int64(*resp.FirewallPolicyResponse.ConsumedStatelessRuleCapacity)
			f1.ConsumedStatelessRuleCapacity = &consumedStatelessRuleCapacityCopy
		}
		if resp.FirewallPolicyResponse.Description != nil {
			f1.Description = resp.FirewallPolicyResponse.Description
		}
		if resp.FirewallPolicyResponse.EncryptionConfiguration != nil {
			f1f3 := &svcapitypes.EncryptionConfiguration{}
			if resp.FirewallPolicyResponse.EncryptionConfiguration.KeyId != nil {
				f1f3.KeyID = resp.FirewallPolicyResponse.EncryptionConfiguration.KeyId
			}
			if resp.FirewallPolicyResponse.EncryptionConfiguration.Type != "" {
				f1f3.Type = aws.String(string(resp.FirewallPolicyResponse.EncryptionConfiguration.Type))
			}
			f1.EncryptionConfiguration = f1f3
		}
		if resp.FirewallPolicyResponse.FirewallPolicyArn != nil {
			f1.FirewallPolicyARN = resp.FirewallPolicyResponse.FirewallPolicyArn
		}
		if resp.FirewallPolicyResponse.FirewallPolicyId != nil {
			f1.FirewallPolicyID = resp.FirewallPolicyResponse.FirewallPolicyId
		}
		if resp.FirewallPolicyResponse.FirewallPolicyName != nil {
			f1.FirewallPolicyName = resp.FirewallPolicyResponse.FirewallPolicyName
		}
		if resp.FirewallPolicyResponse.FirewallPolicyStatus != "" {
			f1.FirewallPolicyStatus = aws.String(string(resp.FirewallPolicyResponse.FirewallPolicyStatus))
		}
		if resp.FirewallPolicyResponse.LastModifiedTime != nil {
			f1.LastModifiedTime = &metav1.Time{*resp.FirewallPolicyResponse.LastModifiedTime}
		}
		if resp.FirewallPolicyResponse.NumberOfAssociations != nil {
			numberOfAssociationsCopy := int64(*resp.FirewallPolicyResponse.NumberOfAssociations)
			f1.NumberOfAssociations = &numberOfAssociationsCopy
		}
		if resp.FirewallPolicyResponse.Tags != nil {
			f1f10 := []*svcapitypes.Tag{}
			for _, f1f10iter := range resp.FirewallPolicyResponse.Tags {
				f1f10elem := &svcapitypes.Tag{}
				if f1f10iter.Key != nil {
					f1f10elem.Key = f1f10iter.Key
				}
				if f1f10iter.Value != nil {
					f1f10elem.Value = f1f10iter.Value
				}
				f1f10 = append(f1f10, f1f10elem)
			}
			f1.Tags = f1f10
		}
		ko.Status.FirewallPolicyResponse = f1
	} else {
		ko.Status.FirewallPolicyResponse = nil
	}
	if resp.UpdateToken != nil {
		ko.Status.UpdateToken = resp.UpdateToken
	} else {
		ko.Status.UpdateToken = nil
	}

	rm.setStatusDefaults(ko)
	return &resource{ko}, nil
}

// requiredFieldsMissingFromReadOneInput returns true if there are any fields
// for the ReadOne Input shape that are required but not present in the
// resource's Spec or Status
func (rm *resourceManager) requiredFieldsMissingFromReadOneInput(
	r *resource,
) bool {
	return false
}

// newDescribeRequestPayload returns SDK-specific struct for the HTTP request
// payload of the Describe API call for the resource
func (rm *resourceManager) newDescribeRequestPayload(
	r *resource,
) (*svcsdk.DescribeFirewallPolicyInput, error) {
	res := &svcsdk.DescribeFirewallPolicyInput{}

	if r.ko.Status.ACKResourceMetadata != nil && r.ko.Status.ACKResourceMetadata.ARN != nil {
		res.FirewallPolicyArn = (*string)(r.ko.Status.ACKResourceMetadata.ARN)
	}
	if r.ko.Spec.FirewallPolicyName != nil {
		res.FirewallPolicyName = r.ko.Spec.FirewallPolicyName
	}

	return res, nil
}

// sdkCreate creates the supplied resource in the backend AWS service API and
// returns a copy of the resource with resource fields (in both Spec and
// Status) filled in with values from the CREATE API operation's Output shape.
func (rm *resourceManager) sdkCreate(
	ctx context.Context,
	desired *resource,
) (created *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.sdkCreate")
	defer func() {
		exit(err)
	}()
	input, err := rm.newCreateRequestPayload(ctx, desired)
	if err != nil {
		return nil, err
	}

	var resp *svcsdk.CreateFirewallPolicyOutput
	_ = resp
	resp, err = rm.sdkapi.CreateFirewallPolicy(ctx, input)
	rm.metrics.RecordAPICall("CREATE", "CreateFirewallPolicy", err)
	if err != nil {
		return nil, err
	}
	// Merge in the information we read from the API call above to the copy of
	// the original Kubernetes object we passed to the function
	ko := desired.ko.DeepCopy()

	if resp.FirewallPolicyResponse != nil {
		f0 := &svcapitypes.FirewallPolicyResponse{}
		if resp.FirewallPolicyResponse.ConsumedStatefulRuleCapacity != nil {
			consumedStatefulRuleCapacityCopy := int64(*resp.FirewallPolicyResponse.ConsumedStatefulRuleCapacity)
			f0.ConsumedStatefulRuleCapacity = &consumedStatefulRuleCapacityCopy
		}
		if resp.FirewallPolicyResponse.ConsumedStatelessRuleCapacity != nil {
			consumedStatelessRuleCapacityCopy := int64(*resp.FirewallPolicyResponse.ConsumedStatelessRuleCapacity)
			f0.ConsumedStatelessRuleCapacity = &consumedStatelessRuleCapacityCopy
		}
		if resp.FirewallPolicyResponse.Description != nil {
			f0.Description = resp.FirewallPolicyResponse.Description
		}
		if resp.FirewallPolicyResponse.EncryptionConfiguration != nil {
			f0f3 := &svcapitypes.EncryptionConfiguration{}
			if resp.FirewallPolicyResponse.EncryptionConfiguration.KeyId != nil {
				f0f3.KeyID = resp.FirewallPolicyResponse.EncryptionConfiguration.KeyId
			}
			if resp.FirewallPolicyResponse.EncryptionConfiguration.Type != "" {
				f0f3.Type = aws.String(string(resp.FirewallPolicyResponse.EncryptionConfiguration.Type))
			}
			f0.EncryptionConfiguration = f0f3
		}
		if resp.FirewallPolicyResponse.FirewallPolicyArn != nil {
			f0.FirewallPolicyARN = resp.FirewallPolicyResponse.FirewallPolicyArn
		}
		if resp.FirewallPolicyResponse.FirewallPolicyId != nil {
			f0.FirewallPolicyID = resp.FirewallPolicyResponse.FirewallPolicyId
		}
		if resp.FirewallPolicyResponse.FirewallPolicyName != nil {
			f0.FirewallPolicyName = resp.FirewallPolicyResponse.FirewallPolicyName
		}
		if resp.FirewallPolicyResponse.FirewallPolicyStatus != "" {
			f0.FirewallPolicyStatus = aws.String(string(resp.FirewallPolicyResponse.FirewallPolicyStatus))
		}
		if resp.FirewallPolicyResponse.LastModifiedTime != nil {
			f0.LastModifiedTime = &metav1.Time{*resp.FirewallPolicyResponse.LastModifiedTime}
		}
		if resp.FirewallPolicyResponse.NumberOfAssociations != nil {
			numberOfAssociationsCopy := int64(*resp.FirewallPolicyResponse.NumberOfAssociations)
			f0.NumberOfAssociations = &numberOfAssociationsCopy
		}
		if resp.FirewallPolicyResponse.Tags != nil {
			f0f10 := []*svcapitypes.Tag{}
			for _, f0f10iter := range resp.FirewallPolicyResponse.Tags {
				f0f10elem := &svcapitypes.Tag{}
				if f0f10iter.Key != nil {
					f0f10elem.Key = f0f10iter.Key
				}
				if f0f10iter.Value != nil {
					f0f10elem.Value = f0f10iter.Value
				}
				f0f10 = append(f0f10, f0f10elem)
			}
			f0.Tags = f0f10
		}
		ko.Status.FirewallPolicyResponse = f0
	} else {
		ko.Status.FirewallPolicyResponse = nil
	}
	if resp.UpdateToken != nil {
		ko.Status.UpdateToken = resp.UpdateToken
	} else {
		ko.Status.UpdateToken = nil
	}

	rm.setStatusDefaults(ko)
	return &resource{ko}, nil
}

// newCreateRequestPayload returns an SDK-specific struct for the HTTP request
// payload of the Create API call for the resource
func (rm *resourceManager) newCreateRequestPayload(
	ctx context.Context,
	r *resource,
) (*svcsdk.CreateFirewallPolicyInput, error) {
	res := &svcsdk.CreateFirewallPolicyInput{}

	if r.ko.Spec.Description != nil {
		res.Description = r.ko.Spec.Description
	}
	if r.ko.Spec.EncryptionConfiguration != nil {
		f1 := &svcsdktypes.EncryptionConfiguration{}
		if r.ko.Spec.EncryptionConfiguration.KeyID != nil {
			f1.KeyId = r.ko.Spec.EncryptionConfiguration.KeyID
		}
		if r.ko.Spec.EncryptionConfiguration.Type != nil {
			f1.Type = svcsdktypes.EncryptionType(*r.ko.Spec.EncryptionConfiguration.Type)
		}
		res.EncryptionConfiguration = f1
	}
	if r.ko.Spec.FirewallPolicy != nil {
		f2 := &svcsdktypes.FirewallPolicy{}
		if r.ko.Spec.FirewallPolicy.PolicyVariables != nil {
			f2f0 := &svcsdktypes.PolicyVariables{}
			if r.ko.Spec.FirewallPolicy.PolicyVariables.RuleVariables != nil {
				f2f0f0 := map[string]svcsdktypes.IPSet{}
				for f2f0f0key, f2f0f0valiter := range r.ko.Spec.FirewallPolicy.PolicyVariables.RuleVariables {
					f2f0f0val := &svcsdktypes.IPSet{}
					if f2f0f0valiter.Definition != nil {
						f2f0f0val.Definition = aws.ToStringSlice(f2f0f0valiter.Definition)
					}
					f2f0f0[f2f0f0key] = *f2f0f0val
				}
				f2f0.RuleVariables = f2f0f0
			}
			f2.PolicyVariables = f2f0
		}
		if r.ko.Spec.FirewallPolicy.StatefulDefaultActions != nil {
			f2.StatefulDefaultActions = aws.ToStringSlice(r.ko.Spec.FirewallPolicy.StatefulDefaultActions)
		}
		if r.ko.Spec.FirewallPolicy.StatefulEngineOptions != nil {
			f2f2 := &svcsdktypes.StatefulEngineOptions{}
			if r.ko.Spec.FirewallPolicy.StatefulEngineOptions.RuleOrder != nil {
				f2f2.RuleOrder = svcsdktypes.RuleOrder(*r.ko.Spec.FirewallPolicy.StatefulEngineOptions.RuleOrder)
			}
			if r.ko.Spec.FirewallPolicy.StatefulEngineOptions.StreamExceptionPolicy != nil {
				f2f2.StreamExceptionPolicy = svcsdktypes.StreamExceptionPolicy(*r.ko.Spec.FirewallPolicy.StatefulEngineOptions.StreamExceptionPolicy)
			}
			f2.StatefulEngineOptions = f2f2
		}
		if r.ko.Spec.FirewallPolicy.StatefulRuleGroupReferences != nil {
			f2f3 := []svcsdktypes.StatefulRuleGroupReference{}
			for _, f2f3iter := range r.ko.Spec.FirewallPolicy.StatefulRuleGroupReferences {
				f2f3elem := &svcsdktypes.StatefulRuleGroupReference{}
				if f2f3iter.Override != nil {
					f2f3elemf0 := &svcsdktypes.StatefulRuleGroupOverride{}
					if f2f3iter.Override.Action != nil {
						f2f3elemf0.Action = svcsdktypes.OverrideAction(*f2f3iter.Override.Action)
					}
					f2f3elem.Override = f2f3elemf0
				}
				if f2f3iter.Priority != nil {
					priorityCopy0 := *f2f3iter.Priority
					if priorityCopy0 > math.MaxInt32 || priorityCopy0 < math.MinInt32 {
						return nil, fmt.Errorf("error: field Priority is of type int32")
					}
					priorityCopy := int32(priorityCopy0)
					f2f3elem.Priority = &priorityCopy
				}
				if f2f3iter.ResourceARN != nil {
					f2f3elem.ResourceArn = f2f3iter.ResourceARN
				}
				f2f3 = append(f2f3, *f2f3elem)
			}
			f2.StatefulRuleGroupReferences = f2f3
		}
		if r.ko.Spec.FirewallPolicy.StatelessCustomActions != nil {
			f2f4 := []svcsdktypes.CustomAction{}
			for _, f2f4iter := range r.ko.Spec.FirewallPolicy.StatelessCustomActions {
				f2f4elem := &svcsdktypes.CustomAction{}
				if f2f4iter.ActionDefinition != nil {
					f2f4elemf0 := &svcsdktypes.ActionDefinition{}
					if f2f4iter.ActionDefinition.PublishMetricAction != nil {
						f2f4elemf0f0 := &svcsdktypes.PublishMetricAction{}
						if f2f4iter.ActionDefinition.PublishMetricAction.Dimensions != nil {
							f2f4elemf0f0f0 := []svcsdktypes.Dimension{}
							for _, f2f4elemf0f0f0iter := range f2f4iter.ActionDefinition.PublishMetricAction.Dimensions {
								f2f4elemf0f0f0elem := &svcsdktypes.Dimension{}
								if f2f4elemf0f0f0iter.Value != nil {
									f2f4elemf0f0f0elem.Value = f2f4elemf0f0f0iter.Value
								}
								f2f4elemf0f0f0 = append(f2f4elemf0f0f0, *f2f4elemf0f0f0elem)
							}
							f2f4elemf0f0.Dimensions = f2f4elemf0f0f0
						}
						f2f4elemf0.PublishMetricAction = f2f4elemf0f0
					}
					f2f4elem.ActionDefinition = f2f4elemf0
				}
				if f2f4iter.ActionName != nil {
					f2f4elem.ActionName = f2f4iter.ActionName
				}
				f2f4 = append(f2f4, *f2f4elem)
			}
			f2.StatelessCustomActions = f2f4
		}
		if r.ko.Spec.FirewallPolicy.StatelessDefaultActions != nil {
			f2.StatelessDefaultActions = aws.ToStringSlice(r.ko.Spec.FirewallPolicy.StatelessDefaultActions)
		}
		if r.ko.Spec.FirewallPolicy.StatelessFragmentDefaultActions != nil {
			f2.StatelessFragmentDefaultActions = aws.ToStringSlice(r.ko.Spec.FirewallPolicy.StatelessFragmentDefaultActions)
		}
		if r.ko.Spec.FirewallPolicy.StatelessRuleGroupReferences != nil {
			f2f7 := []svcsdktypes.StatelessRuleGroupReference{}
			for _, f2f7iter := range r.ko.Spec.FirewallPolicy.StatelessRuleGroupReferences {
				f2f7elem := &svcsdktypes.StatelessRuleGroupReference{}
				if f2f7iter.Priority != nil {
					priorityCopy0 := *f2f7iter.Priority
					if priorityCopy0 > math.MaxInt32 || priorityCopy0 < math.MinInt32 {
						return nil, fmt.Errorf("error: field Priority is of type int32")
					}
					priorityCopy := int32(priorityCopy0)
					f2f7elem.Priority = &priorityCopy
				}
				if f2f7iter.ResourceARN != nil {
					f2f7elem.ResourceArn = f2f7iter.ResourceARN
				}
				f2f7 = append(f2f7, *f2f7elem)
			}
			f2.StatelessRuleGroupReferences = f2f7
		}
		if r.ko.Spec.FirewallPolicy.TLSInspectionConfigurationARN != nil {
			f2.TLSInspectionConfigurationArn = r.ko.Spec.FirewallPolicy.TLSInspectionConfigurationARN
		}
		res.FirewallPolicy = f2
	}
	if r.ko.Spec.FirewallPolicyName != nil {
		res.FirewallPolicyName = r.ko.Spec.FirewallPolicyName
	}
	if r.ko.Spec.Tags != nil {
		f4 := []svcsdktypes.Tag{}
		for _, f4iter := range r.ko.Spec.Tags {
			f4elem := &svcsdktypes.Tag{}
			if f4iter.Key != nil {
				f4elem.Key = f4iter.Key
			}
			if f4iter.Value != nil {
				f4elem.Value = f4iter.Value
			}
			f4 = append(f4, *f4elem)
		}
		res.Tags = f4
	}

	return res, nil
}

// sdkUpdate patches the supplied resource in the backend AWS service API and
// returns a new resource with updated fields.
func (rm *resourceManager) sdkUpdate(
	ctx context.Context,
	desired *resource,
	latest *resource,
	delta *ackcompare.Delta,
) (updated *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.sdkUpdate")
	defer func() {
		exit(err)
	}()
	input, err := rm.newUpdateRequestPayload(ctx, desired, delta)
	if err != nil {
		return nil, err
	}

	var resp *svcsdk.UpdateFirewallPolicyOutput
	_ = resp
	resp, err = rm.sdkapi.UpdateFirewallPolicy(ctx, input)
	rm.metrics.RecordAPICall("UPDATE", "UpdateFirewallPolicy", err)
	if err != nil {
		return nil, err
	}
	// Merge in the information we read from the API call above to the copy of
	// the original Kubernetes object we passed to the function
	ko := desired.ko.DeepCopy()

	if resp.FirewallPolicyResponse != nil {
		f0 := &svcapitypes.FirewallPolicyResponse{}
		if resp.FirewallPolicyResponse.ConsumedStatefulRuleCapacity != nil {
			consumedStatefulRuleCapacityCopy := int64(*resp.FirewallPolicyResponse.ConsumedStatefulRuleCapacity)
			f0.ConsumedStatefulRuleCapacity = &consumedStatefulRuleCapacityCopy
		}
		if resp.FirewallPolicyResponse.ConsumedStatelessRuleCapacity != nil {
			consumedStatelessRuleCapacityCopy := int64(*resp.FirewallPolicyResponse.ConsumedStatelessRuleCapacity)
			f0.ConsumedStatelessRuleCapacity = &consumedStatelessRuleCapacityCopy
		}
		if resp.FirewallPolicyResponse.Description != nil {
			f0.Description = resp.FirewallPolicyResponse.Description
		}
		if resp.FirewallPolicyResponse.EncryptionConfiguration != nil {
			f0f3 := &svcapitypes.EncryptionConfiguration{}
			if resp.FirewallPolicyResponse.EncryptionConfiguration.KeyId != nil {
				f0f3.KeyID = resp.FirewallPolicyResponse.EncryptionConfiguration.KeyId
			}
			if resp.FirewallPolicyResponse.EncryptionConfiguration.Type != "" {
				f0f3.Type = aws.String(string(resp.FirewallPolicyResponse.EncryptionConfiguration.Type))
			}
			f0.EncryptionConfiguration = f0f3
		}
		if resp.FirewallPolicyResponse.FirewallPolicyArn != nil {
			f0.FirewallPolicyARN = resp.FirewallPolicyResponse.FirewallPolicyArn
		}
		if resp.FirewallPolicyResponse.FirewallPolicyId != nil {
			f0.FirewallPolicyID = resp.FirewallPolicyResponse.FirewallPolicyId
		}
		if resp.FirewallPolicyResponse.FirewallPolicyName != nil {
			f0.FirewallPolicyName = resp.FirewallPolicyResponse.FirewallPolicyName
		}
		if resp.FirewallPolicyResponse.FirewallPolicyStatus != "" {
			f0.FirewallPolicyStatus = aws.String(string(resp.FirewallPolicyResponse.FirewallPolicyStatus))
		}
		if resp.FirewallPolicyResponse.LastModifiedTime != nil {
			f0.LastModifiedTime = &metav1.Time{*resp.FirewallPolicyResponse.LastModifiedTime}
		}
		if resp.FirewallPolicyResponse.NumberOfAssociations != nil {
			numberOfAssociationsCopy := int64(*resp.FirewallPolicyResponse.NumberOfAssociations)
			f0.NumberOfAssociations = &numberOfAssociationsCopy
		}
		if resp.FirewallPolicyResponse.Tags != nil {
			f0f10 := []*svcapitypes.Tag{}
			for _, f0f10iter := range resp.FirewallPolicyResponse.Tags {
				f0f10elem := &svcapitypes.Tag{}
				if f0f10iter.Key != nil {
					f0f10elem.Key = f0f10iter.Key
				}
				if f0f10iter.Value != nil {
					f0f10elem.Value = f0f10iter.Value
				}
				f0f10 = append(f0f10, f0f10elem)
			}
			f0.Tags = f0f10
		}
		ko.Status.FirewallPolicyResponse = f0
	} else {
		ko.Status.FirewallPolicyResponse = nil
	}
	if resp.UpdateToken != nil {
		ko.Status.UpdateToken = resp.UpdateToken
	} else {
		ko.Status.UpdateToken = nil
	}

	rm.setStatusDefaults(ko)
	return &resource{ko}, nil
}

// newUpdateRequestPayload returns an SDK-specific struct for the HTTP request
// payload of the Update API call for the resource
func (rm *resourceManager) newUpdateRequestPayload(
	ctx context.Context,
	r *resource,
	delta *ackcompare.Delta,
) (*svcsdk.UpdateFirewallPolicyInput, error) {
	res := &svcsdk.UpdateFirewallPolicyInput{}

	if r.ko.Spec.Description != nil {
		res.Description = r.ko.Spec.Description
	}
	if r.ko.Spec.EncryptionConfiguration != nil {
		f2 := &svcsdktypes.EncryptionConfiguration{}
		if r.ko.Spec.EncryptionConfiguration.KeyID != nil {
			f2.KeyId = r.ko.Spec.EncryptionConfiguration.KeyID
		}
		if r.ko.Spec.EncryptionConfiguration.Type != nil {
			f2.Type = svcsdktypes.EncryptionType(*r.ko.Spec.EncryptionConfiguration.Type)
		}
		res.EncryptionConfiguration = f2
	}
	if r.ko.Spec.FirewallPolicy != nil {
		f3 := &svcsdktypes.FirewallPolicy{}
		if r.ko.Spec.FirewallPolicy.PolicyVariables != nil {
			f3f0 := &svcsdktypes.PolicyVariables{}
			if r.ko.Spec.FirewallPolicy.PolicyVariables.RuleVariables != nil {
				f3f0f0 := map[string]svcsdktypes.IPSet{}
				for f3f0f0key, f3f0f0valiter := range r.ko.Spec.FirewallPolicy.PolicyVariables.RuleVariables {
					f3f0f0val := &svcsdktypes.IPSet{}
					if f3f0f0valiter.Definition != nil {
						f3f0f0val.Definition = aws.ToStringSlice(f3f0f0valiter.Definition)
					}
					f3f0f0[f3f0f0key] = *f3f0f0val
				}
				f3f0.RuleVariables = f3f0f0
			}
			f3.PolicyVariables = f3f0
		}
		if r.ko.Spec.FirewallPolicy.StatefulDefaultActions != nil {
			f3.StatefulDefaultActions = aws.ToStringSlice(r.ko.Spec.FirewallPolicy.StatefulDefaultActions)
		}
		if r.ko.Spec.FirewallPolicy.StatefulEngineOptions != nil {
			f3f2 := &svcsdktypes.StatefulEngineOptions{}
			if r.ko.Spec.FirewallPolicy.StatefulEngineOptions.RuleOrder != nil {
				f3f2.RuleOrder = svcsdktypes.RuleOrder(*r.ko.Spec.FirewallPolicy.StatefulEngineOptions.RuleOrder)
			}
			if r.ko.Spec.FirewallPolicy.StatefulEngineOptions.StreamExceptionPolicy != nil {
				f3f2.StreamExceptionPolicy = svcsdktypes.StreamExceptionPolicy(*r.ko.Spec.FirewallPolicy.StatefulEngineOptions.StreamExceptionPolicy)
			}
			f3.StatefulEngineOptions = f3f2
		}
		if r.ko.Spec.FirewallPolicy.StatefulRuleGroupReferences != nil {
			f3f3 := []svcsdktypes.StatefulRuleGroupReference{}
			for _, f3f3iter := range r.ko.Spec.FirewallPolicy.StatefulRuleGroupReferences {
				f3f3elem := &svcsdktypes.StatefulRuleGroupReference{}
				if f3f3iter.Override != nil {
					f3f3elemf0 := &svcsdktypes.StatefulRuleGroupOverride{}
					if f3f3iter.Override.Action != nil {
						f3f3elemf0.Action = svcsdktypes.OverrideAction(*f3f3iter.Override.Action)
					}
					f3f3elem.Override = f3f3elemf0
				}
				if f3f3iter.Priority != nil {
					priorityCopy0 := *f3f3iter.Priority
					if priorityCopy0 > math.MaxInt32 || priorityCopy0 < math.MinInt32 {
						return nil, fmt.Errorf("error: field Priority is of type int32")
					}
					priorityCopy := int32(priorityCopy0)
					f3f3elem.Priority = &priorityCopy
				}
				if f3f3iter.ResourceARN != nil {
					f3f3elem.ResourceArn = f3f3iter.ResourceARN
				}
				f3f3 = append(f3f3, *f3f3elem)
			}
			f3.StatefulRuleGroupReferences = f3f3
		}
		if r.ko.Spec.FirewallPolicy.StatelessCustomActions != nil {
			f3f4 := []svcsdktypes.CustomAction{}
			for _, f3f4iter := range r.ko.Spec.FirewallPolicy.StatelessCustomActions {
				f3f4elem := &svcsdktypes.CustomAction{}
				if f3f4iter.ActionDefinition != nil {
					f3f4elemf0 := &svcsdktypes.ActionDefinition{}
					if f3f4iter.ActionDefinition.PublishMetricAction != nil {
						f3f4elemf0f0 := &svcsdktypes.PublishMetricAction{}
						if f3f4iter.ActionDefinition.PublishMetricAction.Dimensions != nil {
							f3f4elemf0f0f0 := []svcsdktypes.Dimension{}
							for _, f3f4elemf0f0f0iter := range f3f4iter.ActionDefinition.PublishMetricAction.Dimensions {
								f3f4elemf0f0f0elem := &svcsdktypes.Dimension{}
								if f3f4elemf0f0f0iter.Value != nil {
									f3f4elemf0f0f0elem.Value = f3f4elemf0f0f0iter.Value
								}
								f3f4elemf0f0f0 = append(f3f4elemf0f0f0, *f3f4elemf0f0f0elem)
							}
							f3f4elemf0f0.Dimensions = f3f4elemf0f0f0
						}
						f3f4elemf0.PublishMetricAction = f3f4elemf0f0
					}
					f3f4elem.ActionDefinition = f3f4elemf0
				}
				if f3f4iter.ActionName != nil {
					f3f4elem.ActionName = f3f4iter.ActionName
				}
				f3f4 = append(f3f4, *f3f4elem)
			}
			f3.StatelessCustomActions = f3f4
		}
		if r.ko.Spec.FirewallPolicy.StatelessDefaultActions != nil {
			f3.StatelessDefaultActions = aws.ToStringSlice(r.ko.Spec.FirewallPolicy.StatelessDefaultActions)
		}
		if r.ko.Spec.FirewallPolicy.StatelessFragmentDefaultActions != nil {
			f3.StatelessFragmentDefaultActions = aws.ToStringSlice(r.ko.Spec.FirewallPolicy.StatelessFragmentDefaultActions)
		}
		if r.ko.Spec.FirewallPolicy.StatelessRuleGroupReferences != nil {
			f3f7 := []svcsdktypes.StatelessRuleGroupReference{}
			for _, f3f7iter := range r.ko.Spec.FirewallPolicy.StatelessRuleGroupReferences {
				f3f7elem := &svcsdktypes.StatelessRuleGroupReference{}
				if f3f7iter.Priority != nil {
					priorityCopy0 := *f3f7iter.Priority
					if priorityCopy0 > math.MaxInt32 || priorityCopy0 < math.MinInt32 {
						return nil, fmt.Errorf("error: field Priority is of type int32")
					}
					priorityCopy := int32(priorityCopy0)
					f3f7elem.Priority = &priorityCopy
				}
				if f3f7iter.ResourceARN != nil {
					f3f7elem.ResourceArn = f3f7iter.ResourceARN
				}
				f3f7 = append(f3f7, *f3f7elem)
			}
			f3.StatelessRuleGroupReferences = f3f7
		}
		if r.ko.Spec.FirewallPolicy.TLSInspectionConfigurationARN != nil {
			f3.TLSInspectionConfigurationArn = r.ko.Spec.FirewallPolicy.TLSInspectionConfigurationARN
		}
		res.FirewallPolicy = f3
	}
	if r.ko.Status.ACKResourceMetadata != nil && r.ko.Status.ACKResourceMetadata.ARN != nil {
		res.FirewallPolicyArn = (*string)(r.ko.Status.ACKResourceMetadata.ARN)
	}
	if r.ko.Spec.FirewallPolicyName != nil {
		res.FirewallPolicyName = r.ko.Spec.FirewallPolicyName
	}
	if r.ko.Status.UpdateToken != nil {
		res.UpdateToken = r.ko.Status.UpdateToken
	}

	return res, nil
}

// sdkDelete deletes the supplied resource in the backend AWS service API
func (rm *resourceManager) sdkDelete(
	ctx context.Context,
	r *resource,
) (latest *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.sdkDelete")
	defer func() {
		exit(err)
	}()
	input, err := rm.newDeleteRequestPayload(r)
	if err != nil {
		return nil, err
	}
	var resp *svcsdk.DeleteFirewallPolicyOutput
	_ = resp
	resp, err = rm.sdkapi.DeleteFirewallPolicy(ctx, input)
	rm.metrics.RecordAPICall("DELETE", "DeleteFirewallPolicy", err)
	return nil, err
}

// newDeleteRequestPayload returns an SDK-specific struct for the HTTP request
// payload of the Delete API call for the resource
func (rm *resourceManager) newDeleteRequestPayload(
	r *resource,
) (*svcsdk.DeleteFirewallPolicyInput, error) {
	res := &svcsdk.DeleteFirewallPolicyInput{}

	if r.ko.Status.ACKResourceMetadata != nil && r.ko.Status.ACKResourceMetadata.ARN != nil {
		res.FirewallPolicyArn = (*string)(r.ko.Status.ACKResourceMetadata.ARN)
	}
	if r.ko.Spec.FirewallPolicyName != nil {
		res.FirewallPolicyName = r.ko.Spec.FirewallPolicyName
	}

	return res, nil
}

// setStatusDefaults sets default properties into supplied custom resource
func (rm *resourceManager) setStatusDefaults(
	ko *svcapitypes.FirewallPolicy,
) {
	if ko.Status.ACKResourceMetadata == nil {
		ko.Status.ACKResourceMetadata = &ackv1alpha1.ResourceMetadata{}
	}
	if ko.Status.ACKResourceMetadata.Region == nil {
		ko.Status.ACKResourceMetadata.Region = &rm.awsRegion
	}
	if ko.Status.ACKResourceMetadata.OwnerAccountID == nil {
		ko.Status.ACKResourceMetadata.OwnerAccountID = &rm.awsAccountID
	}
	if ko.Status.Conditions == nil {
		ko.Status.Conditions = []*ackv1alpha1.Condition{}
	}
}

// updateConditions returns updated resource, true; if conditions were updated
// else it returns nil, false
func (rm *resourceManager) updateConditions(
	r *resource,
	onSuccess bool,
	err error,
) (*resource, bool) {
	ko := r.ko.DeepCopy()
	rm.setStatusDefaults(ko)

	// Terminal condition
	var terminalCondition *ackv1alpha1.Condition = nil
	var recoverableCondition *ackv1alpha1.Condition = nil
	var syncCondition *ackv1alpha1.Condition = nil
	for _, condition := range ko.Status.Conditions {
		if condition.Type == ackv1alpha1.ConditionTypeTerminal {
			terminalCondition = condition
		}
		if condition.Type == ackv1alpha1.ConditionTypeRecoverable {
			recoverableCondition = condition
		}
		if condition.Type == ackv1alpha1.ConditionTypeResourceSynced {
			syncCondition = condition
		}
	}
	var termError *ackerr.TerminalError
	if rm.terminalAWSError(err) || err == ackerr.SecretTypeNotSupported || err == ackerr.SecretNotFound || errors.As(err, &termError) {
		if terminalCondition == nil {
			terminalCondition = &ackv1alpha1.Condition{
				Type: ackv1alpha1.ConditionTypeTerminal,
			}
			ko.Status.Conditions = append(ko.Status.Conditions, terminalCondition)
		}
		var errorMessage = ""
		if err == ackerr.SecretTypeNotSupported || err == ackerr.SecretNotFound || errors.As(err, &termError) {
			errorMessage = err.Error()
		} else {
			awsErr, _ := ackerr.AWSError(err)
			errorMessage = awsErr.Error()
		}
		terminalCondition.Status = corev1.ConditionTrue
		terminalCondition.Message = &errorMessage
	} else {
		// Clear the terminal condition if no longer present
		if terminalCondition != nil {
			terminalCondition.Status = corev1.ConditionFalse
			terminalCondition.Message = nil
		}
		// Handling Recoverable Conditions
		if err != nil {
			if recoverableCondition == nil {
				// Add a new Condition containing a non-terminal error
				recoverableCondition = &ackv1alpha1.Condition{
					Type: ackv1alpha1.ConditionTypeRecoverable,
				}
				ko.Status.Conditions = append(ko.Status.Conditions, recoverableCondition)
			}
			recoverableCondition.Status = corev1.ConditionTrue
			awsErr, _ := ackerr.AWSError(err)
			errorMessage := err.Error()
			if awsErr != nil {
				errorMessage = awsErr.Error()
			}
			recoverableCondition.Message = &errorMessage
		} else if recoverableCondition != nil {
			recoverableCondition.Status = corev1.ConditionFalse
			recoverableCondition.Message = nil
		}
	}
	// Required to avoid the "declared but not used" error in the default case
	_ = syncCondition
	if terminalCondition != nil || recoverableCondition != nil || syncCondition != nil {
		return &resource{ko}, true // updated
	}
	return nil, false // not updated
}

// terminalAWSError returns awserr, true; if the supplied error is an aws Error type
// and if the exception indicates that it is a Terminal exception
// 'Terminal' exception are specified in generator configuration
func (rm *resourceManager) terminalAWSError(err error) bool {
	if err == nil {
		return false
	}

	var terminalErr smithy.APIError
	if !errors.As(err, &terminalErr) {
		return false
	}
	switch terminalErr.ErrorCode() {
	case "InvalidRequestException":
		return true
	default:
		return false
	}
}
