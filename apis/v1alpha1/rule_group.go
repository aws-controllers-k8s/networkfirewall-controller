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

package v1alpha1

import (
	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RuleGroupSpec defines the desired state of RuleGroup.
//
// The object that defines the rules in a rule group. This, along with RuleGroupResponse,
// define the rule group. You can retrieve all objects for a rule group by calling
// DescribeRuleGroup.
//
// Network Firewall uses a rule group to inspect and control network traffic.
// You define stateless rule groups to inspect individual packets and you define
// stateful rule groups to inspect packets in the context of their traffic flow.
//
// To use a rule group, you include it by reference in an Network Firewall firewall
// policy, then you use the policy in a firewall. You can reference a rule group
// from more than one firewall policy, and you can use a firewall policy in
// more than one firewall.
type RuleGroupSpec struct {

	// Indicates whether you want Network Firewall to analyze the stateless rules
	// in the rule group for rule behavior such as asymmetric routing. If set to
	// TRUE, Network Firewall runs the analysis and then creates the rule group
	// for you. To run the stateless rule group analyzer without creating the rule
	// group, set DryRun to TRUE.
	AnalyzeRuleGroup *bool `json:"analyzeRuleGroup,omitempty"`
	// The maximum operating resources that this rule group can use. Rule group
	// capacity is fixed at creation. When you update a rule group, you are limited
	// to this capacity. When you reference a rule group from a firewall policy,
	// Network Firewall reserves this capacity for the rule group.
	//
	// You can retrieve the capacity that would be required for a rule group before
	// you create the rule group by calling CreateRuleGroup with DryRun set to TRUE.
	//
	// You can't change or exceed this capacity when you update the rule group,
	// so leave room for your rule group to grow.
	//
	// # Capacity for a stateless rule group
	//
	// For a stateless rule group, the capacity required is the sum of the capacity
	// requirements of the individual rules that you expect to have in the rule
	// group.
	//
	// To calculate the capacity requirement of a single rule, multiply the capacity
	// requirement values of each of the rule's match settings:
	//
	//   - A match setting with no criteria specified has a value of 1.
	//
	//   - A match setting with Any specified has a value of 1.
	//
	//   - All other match settings have a value equal to the number of elements
	//     provided in the setting. For example, a protocol setting ["UDP"] and a
	//     source setting ["10.0.0.0/24"] each have a value of 1. A protocol setting
	//     ["UDP","TCP"] has a value of 2. A source setting ["10.0.0.0/24","10.0.0.1/24","10.0.0.2/24"]
	//     has a value of 3.
	//
	// A rule with no criteria specified in any of its match settings has a capacity
	// requirement of 1. A rule with protocol setting ["UDP","TCP"], source setting
	// ["10.0.0.0/24","10.0.0.1/24","10.0.0.2/24"], and a single specification or
	// no specification for each of the other match settings has a capacity requirement
	// of 6.
	//
	// # Capacity for a stateful rule group
	//
	// For a stateful rule group, the minimum capacity required is the number of
	// individual rules that you expect to have in the rule group.
	// +kubebuilder:validation:Required
	Capacity *int64 `json:"capacity"`
	// A description of the rule group.
	//
	// Regex Pattern: `^.*$`
	Description *string `json:"description,omitempty"`
	// Indicates whether you want Network Firewall to just check the validity of
	// the request, rather than run the request.
	//
	// If set to TRUE, Network Firewall checks whether the request can run successfully,
	// but doesn't actually make the requested changes. The call returns the value
	// that the request would return if you ran it with dry run set to FALSE, but
	// doesn't make additions or changes to your resources. This option allows you
	// to make sure that you have the required permissions to run the request and
	// that your request parameters are valid.
	//
	// If set to FALSE, Network Firewall makes the requested changes to your resources.
	DryRun *bool `json:"dryRun,omitempty"`
	// A complex type that contains settings for encryption of your rule group resources.
	EncryptionConfiguration *EncryptionConfiguration `json:"encryptionConfiguration,omitempty"`
	// An object that defines the rule group rules.
	//
	// You must provide either this rule group setting or a Rules setting, but not
	// both.
	RuleGroup *RuleGroup_SDK `json:"ruleGroup,omitempty"`
	// The descriptive name of the rule group. You can't change the name of a rule
	// group after you create it.
	//
	// Regex Pattern: `^[a-zA-Z0-9-]+$`
	// +kubebuilder:validation:Required
	RuleGroupName *string `json:"ruleGroupName"`
	// A string containing stateful rule group rules specifications in Suricata
	// flat format, with one ruleper line. Use this to import your existing Suricata
	// compatible rule groups.
	//
	// You must provide either this rules setting or a populated RuleGroup setting,
	// but not both.
	//
	// You can provide your rule group specification in Suricata flat format through
	// this setting when you create or update your rule group. The callresponse
	// returns a RuleGroup object that Network Firewall has populated from your
	// string.
	Rules *string `json:"rules,omitempty"`
	// A complex type that contains metadata about the rule group that your own
	// rule group is copied from. You can use the metadata to keep track of updates
	// made to the originating rule group.
	SourceMetadata *SourceMetadata `json:"sourceMetadata,omitempty"`
	// The key:value pairs to associate with the resource.
	Tags []*Tag `json:"tags,omitempty"`
	// Indicates whether the rule group is stateless or stateful. If the rule group
	// is stateless, it containsstateless rules. If it is stateful, it contains
	// stateful rules.
	// +kubebuilder:validation:Required
	Type *string `json:"type_"`
}

// RuleGroupStatus defines the observed state of RuleGroup
type RuleGroupStatus struct {
	// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
	// that is used to contain resource sync state, account ownership,
	// constructed ARN for the resource
	// +kubebuilder:validation:Optional
	ACKResourceMetadata *ackv1alpha1.ResourceMetadata `json:"ackResourceMetadata"`
	// All CRs managed by ACK have a common `Status.Conditions` member that
	// contains a collection of `ackv1alpha1.Condition` objects that describe
	// the various terminal states of the CR and its backend AWS service API
	// resource
	// +kubebuilder:validation:Optional
	Conditions []*ackv1alpha1.Condition `json:"conditions"`
	// The high-level properties of a rule group. This, along with the RuleGroup,
	// define the rule group. You can retrieve all objects for a rule group by calling
	// DescribeRuleGroup.
	// +kubebuilder:validation:Optional
	RuleGroupResponse *RuleGroupResponse `json:"ruleGroupResponse,omitempty"`
	// A token used for optimistic locking. Network Firewall returns a token to
	// your requests that access the rule group. The token marks the state of the
	// rule group resource at the time of the request.
	//
	// To make changes to the rule group, you provide the token in your request.
	// Network Firewall uses the token to ensure that the rule group hasn't changed
	// since you last retrieved it. If it has changed, the operation fails with
	// an InvalidTokenException. If this happens, retrieve the rule group again
	// to get a current copy of it with a current token. Reapply your changes as
	// needed, then try the operation again using the new token.
	//
	// Regex Pattern: `^([0-9a-f]{8})-([0-9a-f]{4}-){3}([0-9a-f]{12})$`
	// +kubebuilder:validation:Optional
	UpdateToken *string `json:"updateToken,omitempty"`
}

// RuleGroup is the Schema for the RuleGroups API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type RuleGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RuleGroupSpec   `json:"spec,omitempty"`
	Status            RuleGroupStatus `json:"status,omitempty"`
}

// RuleGroupList contains a list of RuleGroup
// +kubebuilder:object:root=true
type RuleGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RuleGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RuleGroup{}, &RuleGroupList{})
}
