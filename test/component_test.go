package test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/aws-component-helper"
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

func TestComponent(t *testing.T) {
	// Define the AWS region to use for the tests
	awsRegion := "us-east-2"

	// Initialize the test fixture
	fixture := helper.NewFixture(t, "../", awsRegion, "test/fixtures")

	// Ensure teardown is executed after the test
	defer fixture.TearDown()
	fixture.SetUp(&atmos.Options{})

	// Define the test suite
	fixture.Suite("default", func(t *testing.T, suite *helper.Suite) {
		// Test phase: Validate the functionality of the ALB component
		suite.Test(t, "basic", func(t *testing.T, atm *helper.Atmos) {
			inputs := map[string]interface{}{}
			defer atm.GetAndDestroy("aws-team-roles/basic", "default-test", inputs)
			component := atm.GetAndDeploy("aws-team-roles/basic", "default-test", inputs)
			assert.NotNil(t, component)

			rolesMapArns := atm.OutputMapOfObjects(component, "role_name_role_arn_map")
			assert.Equal(t, 2, len(rolesMapArns))

			client := aws.NewIamClient(t, awsRegion)

			adminRoleName := strings.Split(rolesMapArns["admin"].(string), "/")[1]

			describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
				RoleName: &adminRoleName,
			})
			assert.NoError(t, err)

			awsRole := describeRoleOutput.Role
			assert.Equal(t, adminRoleName, *awsRole.RoleName)
			assert.Equal(t, "Full administration of this account", *awsRole.Description)

			assert.EqualValues(t, 3600, *awsRole.MaxSessionDuration)
			assert.Equal(t, "/", *awsRole.Path)

			assumeRolePolicyDocument, err := url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
			assert.NoError(t, err)

			var assumePolicyDoc AssumeRolePolicyDocument
			err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
			assert.NoError(t, err)

			assert.Equal(t, "Allow", assumePolicyDoc.Statement[0].Effect)
			assert.Contains(t, assumePolicyDoc.Statement[0].Principal.Aws, "root")
			assert.ElementsMatch(t, []string{
				"sts:AssumeRole",
				"sts:SetSourceIdentity",
				"sts:TagSession",
			}, assumePolicyDoc.Statement[0].Action)
			assert.Equal(t, "AssumedRole", assumePolicyDoc.Statement[0].Condition.StringEquals["aws:PrincipalType"])

			// Verify assume role conditions
			assert.NotNil(t, assumePolicyDoc.Statement[0].Condition)

			assert.Equal(t, "Deny", assumePolicyDoc.Statement[1].Effect)
			assert.Contains(t, assumePolicyDoc.Statement[1].Principal.Aws, "root")
			assert.ElementsMatch(t, []string{
				"sts:AssumeRole",
				"sts:SetSourceIdentity",
				"sts:TagSession",
			}, assumePolicyDoc.Statement[1].Action)
			assert.NotNil(t, assumePolicyDoc.Statement[1].Condition)

			attachedPolicies, err := client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
				RoleName: &adminRoleName,
			})
			assert.NoError(t, err)

			expectedPolicies := []string{
				"arn:aws:iam::aws:policy/AdministratorAccess",
			}

			var actualPolicies []string
			for _, policy := range attachedPolicies.AttachedPolicies {
				actualPolicies = append(actualPolicies, *policy.PolicyArn)
			}

			assert.ElementsMatch(t, expectedPolicies, actualPolicies)

			terraformRoleName := strings.Split(rolesMapArns["terraform"].(string), "/")[1]

			describeRoleOutput, err = client.GetRole(context.Background(), &iam.GetRoleInput{
				RoleName: &terraformRoleName,
			})
			assert.NoError(t, err)

			awsRole = describeRoleOutput.Role
			assert.Equal(t, terraformRoleName, *awsRole.RoleName)
			assert.Equal(t, "Role for Terraform administration of this account", *awsRole.Description)

			assert.EqualValues(t, 3600, *awsRole.MaxSessionDuration)
			assert.Equal(t, "/", *awsRole.Path)

			assumeRolePolicyDocument, err = url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
			assert.NoError(t, err)

			err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
			assert.NoError(t, err)

			assert.Equal(t, "Allow", assumePolicyDoc.Statement[0].Effect)
			assert.Contains(t, assumePolicyDoc.Statement[0].Principal.Aws, "root")
			assert.ElementsMatch(t, []string{
				"sts:AssumeRole",
				"sts:SetSourceIdentity",
				"sts:TagSession",
			}, assumePolicyDoc.Statement[0].Action)
			assert.Equal(t, "AssumedRole", assumePolicyDoc.Statement[0].Condition.StringEquals["aws:PrincipalType"])

			// Verify assume role conditions
			assert.NotNil(t, assumePolicyDoc.Statement[0].Condition)

			assert.Equal(t, "Deny", assumePolicyDoc.Statement[1].Effect)
			assert.Contains(t, assumePolicyDoc.Statement[1].Principal.Aws, "root")
			assert.ElementsMatch(t, []string{
				"sts:AssumeRole",
				"sts:SetSourceIdentity",
				"sts:TagSession",
			}, assumePolicyDoc.Statement[1].Action)
			assert.NotNil(t, assumePolicyDoc.Statement[1].Condition)

			attachedPolicies, err = client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
				RoleName: &terraformRoleName,
			})
			assert.NoError(t, err)

			expectedPolicies = []string{
				"arn:aws:iam::aws:policy/AdministratorAccess",
			}

			actualPolicies = []string{}
			for _, policy := range attachedPolicies.AttachedPolicies {
				actualPolicies = append(actualPolicies, *policy.PolicyArn)
			}

			assert.ElementsMatch(t, expectedPolicies, actualPolicies)
		})
	})
}
