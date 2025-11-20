# Extra fake secrets for testing Lacework's secret detection

variable "github_app_private_key" {
  description = "Fake GitHub App private key"
  type        = string
  default = <<-KEY
  -----BEGIN PRIVATE KEY-----
  VERYFAKEPRIVATEKEYDATAFORSCANNERTESTONLY1234567890ABCDEFG
  -----END PRIVATE KEY-----
  KEY
}

variable "circleci_token" {
  description = "Fake CircleCI token"
  default     = "circleci-token-fake-1234567890abcdef"
}

variable "datadog_api_key" {
  description = "Fake Datadog API key"
  default     = "dd_api_key_1234567890abcdefFAKEKEY"
}

locals {
  # Fake Stripe secret key for testing (format: fake_stripe_key_<random>)
  stripe_secret_key = "fake_stripe_key_NOTREAL_1234567890abcdef_FAKE_TEST_ONLY"
  sendgrid_api_key  = "SG.fake-sendgrid-token-1234567890ABCDEFGHIJ"
}

resource "null_resource" "leak_to_logs" {
  triggers = {
    stripe_key  = local.stripe_secret_key
    sendgrid    = local.sendgrid_api_key
    circleci    = var.circleci_token
    datadog_key = var.datadog_api_key
  }

  provisioner "local-exec" {
    command = "echo Writing fake secrets ${local.stripe_secret_key} ${local.sendgrid_api_key}"
  }
}

variable "twilio_auth_token" {
  default = "SK_NOTREAL_FAKE_TWILIO_TOKEN_1234567890abcdef_NOTREAL"
}

resource "kubernetes_secret" "plaintext_secret" {
  metadata {
    name = "plaintext-secret"
  }

  data = {
    username = "admin"
    password = "PlaintextSecretK8s987!"
    api_key  = "k8s_api_key_faketoken_1234567890"
  }
}

output "fake_slack_token" {
  value = "xoxb-NOTREAL-FAKE-SLACK-TOKEN-123456789012-FAKEFAKETOKEN0987654321-NOTREAL"
}

output "fake_newrelic_key" {
  value = "NRII-FAKE-NEWRELIC-INGEST-LICENSE-KEY-1234567890"
}

