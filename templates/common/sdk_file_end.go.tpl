{{ $CRD := .CRD }}
{{ $SDKAPI := .SDKAPI }}

{{ range $specFieldName, $specField := $CRD.Config.Resources.Firewall.Fields -}}

{{- if $specField.From }}
{{- $operationName := $specField.From.Operation }}
{{- $path := $specField.From.Path }}
{{- if (eq $operationName "UpdateLoggingConfiguration") }}

{{- $operation := (index $SDKAPI.API.Operations $operationName) -}}

{{/* Find the structure field within the operation */}}
{{- range $memberRefName, $memberRef := $operation.InputRef.Shape.MemberRefs -}}
{{- if (eq $memberRef.Shape.Type "structure") }}

// new{{ $memberRefName }} returns a {{ $memberRefName }} object
// with each the field set by the resource's corresponding spec field.
func (rm *resourceManager) new{{ $memberRefName }}(
    r *resource,
) *svcsdktypes.{{ $memberRef.ShapeName }} {
    res := &svcsdktypes.{{ $memberRef.ShapeName }}{}

{{ GoCodeSetSDKForStruct $CRD "" "res" $memberRef "" (printf "r.ko.Spec.%s" $specFieldName) 1 }}

    return res
}

{{/* Find the matching Describe* operation */}}
{{- $describeOperationName := (printf "Describe%s" (slice $operationName 6))}}
{{- $field := (index $CRD.SpecFields $specFieldName )}}
{{- $operation := (index $SDKAPI.API.Operations $describeOperationName)}}

// setResource{{ $specFieldName }} sets the `{{ $specFieldName }}` spec field
// given the output of a `{{ $operation.Name }}` operation.
func (rm *resourceManager) setResource{{ $specFieldName }}(
    r *resource,
    resp *svcsdk.{{ $operation.OutputRef.ShapeName }},
) *svcapitypes.{{ $memberRef.ShapeName }} {
    res := &svcapitypes.{{ $memberRef.ShapeName }}{}

{{ GoCodeSetResourceForStruct $CRD $specFieldName "res" $memberRef "resp.LoggingConfiguration" $memberRef 1 }}

    return res
}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
