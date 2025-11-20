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
#############################################################
###########################iam example################
resource "google_project_iam_binding" "iam-role" {
	members = [
		"user:user@example.com",
		]
}

# BAD: IAM binding with overly permissive role
resource "google_project_iam_binding" "admin_binding" {
  project = var.project
  role    = "roles/owner"  # BAD: Owner role is too permissive
  
  members = [
    "user:admin@example.com",
    "serviceAccount:${google_service_account.service_account.email}",
    "allUsers",  # BAD: Public access
  ]
}

# BAD: Firewall rule allowing all traffic
resource "google_compute_firewall" "allow_all" {
  name    = "allow-all-traffic"
  network = google_compute_network.network.name
  
  allow {
    protocol = "tcp"
    ports    = ["0-65535"]  # BAD: All TCP ports
  }
  
  allow {
    protocol = "udp"
    ports    = ["0-65535"]  # BAD: All UDP ports
  }
  
  allow {
    protocol = "icmp"
  }
  
  source_ranges = ["0.0.0.0/0"]  # BAD: From anywhere
  target_tags   = ["web", "db", "app"]  # BAD: Applied to all tags
}

# BAD: Compute instance with public IP and no firewall restrictions
resource "google_compute_instance" "exposed_instance" {
  name         = "exposed-instance"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-9"
    }
    # BAD: No disk encryption
  }

  network_interface {
    network = google_compute_network.network.name
    access_config {
      # BAD: Public IP with no restrictions
    }
  }
  
  # BAD: Service account with too many permissions
  service_account {
    email  = google_service_account.service_account.email
    scopes = ["cloud-platform"]  # BAD: Full cloud platform access
  }
  
  # BAD: No metadata security
  metadata = {
    enable-oslogin = "false"  # BAD: Should be true
  }
}

# BAD: Storage bucket with public access
resource "google_storage_bucket" "public_bucket" {
  name          = "public-bucket-12345"
  location      = "US"
  force_destroy = true
  
  # BAD: Public access
  uniform_bucket_level_access = false
  
  # BAD: No encryption
  # BAD: No versioning
}

resource "google_storage_bucket_iam_binding" "public_binding" {
  bucket = google_storage_bucket.public_bucket.name
  role   = "roles/storage.objectViewer"
  
  members = [
    "allUsers",  # BAD: Public access
    "allAuthenticatedUsers",  # BAD: All authenticated users
  ]
}

# BAD: Cloud SQL instance with public IP and weak password
resource "google_sql_database_instance" "public_db" {
  name             = "public-database-instance"
  database_version = "MYSQL_8_0"
  region           = "us-central1"
  
  settings {
    tier = "db-f1-micro"
    
    ip_configuration {
      ipv4_enabled    = true  # BAD: Public IP enabled
      authorized_networks {
        value = "0.0.0.0/0"  # BAD: Access from anywhere
        name  = "anywhere"
      }
    }
    
    # BAD: No backup configuration
    backup_configuration {
      enabled = false  # BAD: Backups disabled
    }
    
    # BAD: No encryption configuration
    database_flags {
      name  = "skip_ssl"
      value = "on"  # BAD: SSL disabled
    }
  }
}

resource "google_sql_user" "weak_password_user" {
  name     = "admin"
  instance = google_sql_database_instance.public_db.name
  password = "password123"  # BAD: Weak password
}

# BAD: GKE cluster with public endpoint and no network policies
resource "google_container_cluster" "insecure_cluster" {
  name     = "insecure-gke-cluster"
  location = "us-central1-a"
  
  # BAD: Public endpoint
  private_cluster_config {
    enable_private_nodes    = false
    enable_private_endpoint = false
  }
  
  # BAD: Legacy ABAC enabled
  enable_legacy_abac = true
  
  # BAD: No network policy
  network_policy {
    enabled = false
  }
  
  # BAD: No pod security policy
  pod_security_policy_config {
    enabled = false
  }
  
  # BAD: No binary authorization
  # BAD: No workload identity
}

 
