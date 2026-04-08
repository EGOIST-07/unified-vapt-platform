-- VAPT Dashboard MySQL Schema

CREATE DATABASE IF NOT EXISTS vapt_dashboard;
USE vapt_dashboard;

-- Assets table: domains, subdomains, IPs, CIDR ranges
CREATE TABLE assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    asset_type ENUM('domain', 'subdomain', 'ip', 'cidr') NOT NULL,
    owner VARCHAR(255) DEFAULT NULL,
    risk_score INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_asset (asset_name, asset_type),
    INDEX idx_asset_type (asset_type),
    INDEX idx_risk_score (risk_score)
);

-- Scans table: tracks all scan jobs
CREATE TABLE scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    scan_type ENUM('quick', 'network', 'full') NOT NULL,
    scan_status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    INDEX idx_scan_status (scan_status),
    INDEX idx_scan_type (scan_type),
    INDEX idx_asset_scan (asset_id, scan_type)
);

-- Ports table: discovered open ports
CREATE TABLE ports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    port_number INT NOT NULL,
    state ENUM('open', 'closed', 'filtered') DEFAULT 'open',
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    UNIQUE KEY unique_port (asset_id, port_number),
    INDEX idx_port_number (port_number)
);

-- Services table: discovered services on assets
CREATE TABLE services (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    port INT NOT NULL,
    protocol ENUM('tcp', 'udp') DEFAULT 'tcp',
    service_name VARCHAR(100) DEFAULT NULL,
    version VARCHAR(255) DEFAULT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    UNIQUE KEY unique_service (asset_id, port, protocol),
    INDEX idx_port (port),
    INDEX idx_service_name (service_name)
);

-- Vulnerabilities table: all discovered vulnerabilities
CREATE TABLE vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    service_id INT DEFAULT NULL,
    vulnerability_name VARCHAR(500) NOT NULL,
    description TEXT DEFAULT NULL,
    severity ENUM('critical', 'high', 'medium', 'low', 'info') NOT NULL,
    cve_id VARCHAR(20) DEFAULT NULL,
    remediation TEXT DEFAULT NULL,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL,
    INDEX idx_severity (severity),
    INDEX idx_cve (cve_id),
    INDEX idx_asset_vuln (asset_id, severity)
);

-- Users table: authentication
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
