module "aws_saml" {
  source  = "cloudposse/stack-config/yaml//modules/remote-state"
  version = "2.0.0"

  component  = var.aws_saml_component_name
  privileged = true

  ignore_errors = true

  defaults = {
    saml_provider_assume_role_policy = ""
  }

  context = module.this.context
}
