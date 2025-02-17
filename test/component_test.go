package test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
)
type AssumeRolePolicyDocument struct {
    Statement []struct {
        Effect    string `json:"Effect"`
        Principal struct {
            Service string `json:"Service"`
            Aws     string `json:"AWS"`
        } `json:"Principal"`
        Action    []string `json:"Action"`
        Condition struct {
            StringEquals    map[string]string   `json:"StringEquals,omitempty"`
            StringNotEquals map[string][]string `json:"StringNotEquals,omitempty"`
            Null            map[string]string   `json:"Null,omitempty"`
            Bool            map[string]bool     `json:"Bool,omitempty"` // Added Bool for new condition
            StringLike      map[string][]string `json:"StringLike,omitempty"`
        } `json:"Condition"`
    } `json:"Statement"`
}


type ComponentSuite struct {
	helper.TestSuite
}

func (s *ComponentSuite) TestBasic() {
	const component = "aws-team-roles/basic"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	rolesMapArns := atmos.OutputMapOfObjects(s.T(), options, "role_name_role_arn_map")
	assert.Equal(s.T(), 2, len(rolesMapArns))

	client := aws.NewIamClient(s.T(), awsRegion)

	adminRoleName := strings.Split(rolesMapArns["admin"].(string), "/")[1]

	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &adminRoleName,
	})
	assert.NoError(s.T(), err)

	awsRole := describeRoleOutput.Role
	assert.Equal(s.T(), adminRoleName, *awsRole.RoleName)
	assert.Equal(s.T(), "Full administration of this account", *awsRole.Description)

	assert.EqualValues(s.T(), 3600, *awsRole.MaxSessionDuration)
	assert.Equal(s.T(), "/", *awsRole.Path)

	assumeRolePolicyDocument, err := url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
	assert.NoError(s.T(), err)

	var assumePolicyDoc AssumeRolePolicyDocument
	err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
	assert.NoError(s.T(), err)

	assert.Equal(s.T(), "Allow", assumePolicyDoc.Statement[0].Effect)
	assert.Contains(s.T(), assumePolicyDoc.Statement[0].Principal.Aws, "root")
	assert.ElementsMatch(s.T(), []string{
		"sts:AssumeRole",
		"sts:SetSourceIdentity",
		"sts:TagSession",
	}, assumePolicyDoc.Statement[0].Action)
	assert.Equal(s.T(), "AssumedRole", assumePolicyDoc.Statement[0].Condition.StringEquals["aws:PrincipalType"])

	assert.NotNil(s.T(), assumePolicyDoc.Statement[0].Condition)

	assert.Equal(s.T(), "Deny", assumePolicyDoc.Statement[1].Effect)
	assert.Contains(s.T(), assumePolicyDoc.Statement[1].Principal.Aws, "root")
	assert.ElementsMatch(s.T(), []string{
		"sts:AssumeRole",
		"sts:SetSourceIdentity",
		"sts:TagSession",
	}, assumePolicyDoc.Statement[1].Action)
	assert.NotNil(s.T(), assumePolicyDoc.Statement[1].Condition)

	attachedPolicies, err := client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
		RoleName: &adminRoleName,
	})
	assert.NoError(s.T(), err)

	expectedPolicies := []string{
		"arn:aws:iam::aws:policy/AdministratorAccess",
	}

	var actualPolicies []string
	for _, policy := range attachedPolicies.AttachedPolicies {
		actualPolicies = append(actualPolicies, *policy.PolicyArn)
	}

	assert.ElementsMatch(s.T(), expectedPolicies, actualPolicies)

	terraformRoleName := strings.Split(rolesMapArns["terraform"].(string), "/")[1]

	client = aws.NewIamClient(s.T(), awsRegion)

	describeRoleOutput, err = client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &terraformRoleName,
	})
	assert.NoError(s.T(), err)

	awsRole = describeRoleOutput.Role
	assert.Equal(s.T(), terraformRoleName, *awsRole.RoleName)
	assert.Equal(s.T(), "Role for Terraform administration of this account", *awsRole.Description)

	assert.EqualValues(s.T(), 3600, *awsRole.MaxSessionDuration)
	assert.Equal(s.T(), "/", *awsRole.Path)

	assumeRolePolicyDocument, err = url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
	assert.NoError(s.T(), err)

	err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
	assert.NoError(s.T(), err)

	assert.Equal(s.T(), "Allow", assumePolicyDoc.Statement[0].Effect)
	assert.Contains(s.T(), assumePolicyDoc.Statement[0].Principal.Aws, "root")
	assert.ElementsMatch(s.T(), []string{
		"sts:AssumeRole",
		"sts:SetSourceIdentity",
		"sts:TagSession",
	}, assumePolicyDoc.Statement[0].Action)
	assert.Equal(s.T(), "AssumedRole", assumePolicyDoc.Statement[0].Condition.StringEquals["aws:PrincipalType"])

	assert.NotNil(s.T(), assumePolicyDoc.Statement[0].Condition)

	assert.Equal(s.T(), "Deny", assumePolicyDoc.Statement[1].Effect)
	assert.Contains(s.T(), assumePolicyDoc.Statement[1].Principal.Aws, "root")
	assert.ElementsMatch(s.T(), []string{
		"sts:AssumeRole",
		"sts:SetSourceIdentity",
		"sts:TagSession",
	}, assumePolicyDoc.Statement[1].Action)
	assert.NotNil(s.T(), assumePolicyDoc.Statement[1].Condition)

	attachedPolicies, err = client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
		RoleName: &terraformRoleName,
	})
	assert.NoError(s.T(), err)

	expectedPolicies = []string{
		"arn:aws:iam::aws:policy/AdministratorAccess",
	}

	actualPolicies = []string{}
	for _, policy := range attachedPolicies.AttachedPolicies {
		actualPolicies = append(actualPolicies, *policy.PolicyArn)
	}

	assert.ElementsMatch(s.T(), expectedPolicies, actualPolicies)
}

func (s *ComponentSuite) TestEnabledFlag() {
	const component = "aws-team-roles/disabled"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	s.VerifyEnabledFlag(component, stack, nil)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
