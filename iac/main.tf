resource "google_compute_network" "network" {
  name = "sample"
}

resource "google_compute_subnetwork" "subnetwork" {
...
  network       = google_compute_network.network.id
}


resource "google_compute_address" "static" {
  name = "ipv4-address"
}

data "google_compute_image" "debian_image" {
  family  = "debian-9"
  project = var.project
}

resource "google_compute_instance" "instance_with_ip" {
..

  boot_disk {
    initialize_params {
      image = data.google_compute_image.debian_image.self_link
    }
  }

  network_interface {
    network = google_compute_network.network.self_link
    access_config {
      nat_ip = google_compute_address.static.address
    }
  }
}


resource "google_service_account" "service_account" {
  account_id   = var.environment
  display_name = "example Service Account"
}

data "google_iam_policy" "admin" {
  binding {
    role = "roles/iam.serviceAccountUser"

    members = [
      "serviceAccount:google_service_account.service_account.email",
    ]
  }
}

resource "google_compute_firewall" "default" {
  name    = "test-firewall"
  network = google_compute_network.network.name
  allow {
    protocol = "icmp"
  }
  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "1000-2000"]
  }
  source_tags = ["web"]
}
resource "google_compute_firewall" "faulty-firewall" {
  name    = "fault-firewall"
  network = google_compute_network.default.name
  allow {
    protocol = "icmp"
  }
  allow {
    protocol = "tcp"
    ports    = ["ALL"]
  }
  source_ranges = ["0.0.0.0/0"]
}
resource "google_compute_firewall" "allow_all_rdp" {
  name    = "allow-all-rdp"
  network = google_compute_network.network.name
  priority = 1001
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["bastion"]

  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}
resource "google_compute_disk" "problematic-disk" {
..
  disk_encryption_key {}

  }
  physical_block_size_bytes = 4096
}

resource "google_compute_firewall" "destruction-rule" {
  name = "not-so-cool-rule"
  network = google_compute_network.default.name
  allow {
    protocol = "icmp"
    ports = ["ALL"]
  }
  	destination_ranges = ["0.0.0.0/0"]
}
###############some GKE examples ####################
  resource "google_container_cluster" "rule-to-enable-leagacy-abac" {
    name= "some-random"
    location="US"
	enable_legacy_abac = "true"
}

resource "google_container_node_pool" "expose-metadata" {
	node_config {
		workload_metadata_config {
			node_metadata = "EXPOSE"
		}
	}
}

resource "google_container_cluster" "metadata-leagacy-endpoints" {
	metadata {
    disable-legacy-endpoints = false
  }
}


resource "google_container_cluster" "exposing the username and password" {
	master_auth {
	    username = ""
	    password = ""
		client_certificate_config {
			issue_client_certificate = true
	    }
	}
}

resource "google_container_cluster" "disablesecuritypolicy" {
	pod_security_policy_config {
        enabled = "false"
	}
}
resource "google_storage_bucket" "public_gcs_bucket" {
  name                        = "bad-practices-bucket"
  location                    = "US"
  force_destroy               = true
  uniform_bucket_level_access = false
  public_access_prevention    = "unspecified"

  website {
    main_page_suffix = "index.html"
    not_found_page   = "404.html"
  }

  cors {
    origin          = ["*"]
    method          = ["GET", "PUT", "DELETE"]
    response_header = ["*"]
    max_age_seconds = 3600
  }
}

resource "google_storage_bucket_iam_binding" "public_gcs_acl" {
  bucket = google_storage_bucket.public_gcs_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers",
  ]
}
resource "google_compute_instance" "metadata_password" {
  name         = "metadata-password"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = data.google_compute_image.debian_image.self_link
    }
  }

  service_account {
    email  = google_service_account.service_account.email
    scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]
  }

  metadata = {
    windows-password = "PlaintextPassword123!"
    api_key          = "gcp_api_key_notreal_0987654321"
  }

  network_interface {
    network = google_compute_network.network.self_link
    access_config {}
  }
}
resource "google_sql_database_instance" "public_sql" {
  name             = "bad-public-sql"
  region           = "us-central1"
  database_version = "MYSQL_5_7"

  settings {
    tier = "db-f1-micro"

    backup_configuration {
      enabled = false
    }

    ip_configuration {
      ipv4_enabled = true
      require_ssl  = false

      authorized_networks {
        name  = "allow-all"
        value = "0.0.0.0/0"
      }
    }
  }

  deletion_protection = false
}
resource "google_sql_user" "weak_sql_user" {
  instance = google_sql_database_instance.public_sql.name
  name     = "admin"
  password = "PlaintextPass123!"
}
resource "google_project_iam_binding" "all_users_owner" {
  role = "roles/owner"
  members = [
    "allAuthenticatedUsers",
  ]
}
#############################################################
###########################iam example################
resource "google_project_iam_binding" "iam-role" {
	members = [
		"user:user@example.com",
		]
}

 
