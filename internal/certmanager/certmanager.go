// SPDX-FileCopyrightText: 2025 Paulo Almeida <almeidapaulopt@gmail.com>
// SPDX-License-Identifier: MIT

package certmanager

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/almeidapaulopt/tsdproxy/internal/config"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

)

type CertManager struct {
	config config.LetsEncryptConfig
	certManager *autocert.Manager
}

func NewCertManager(cfg config.LetsEncryptConfig) (*CertManager, error) {
	cacheDir := cfg.CacheDir
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			return nil, fmt.Errorf("creating cert cache directory: %w", err)
		}
	}

	m := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			if host == cfg.DomainName {
				return nil
			}
			return fmt.Errorf("disallowed host: %s", host)
		},
	}

	api, err := cloudflare.NewWithToken(cfg.CloudflareAPIToken)
	if err != nil {
		return nil, fmt.Errorf("creating Cloudflare API client: %w", err)
	}

	// Fetch the zone ID
	zoneID, err := api.ZoneIDByName(cfg.DomainName)
	if err != nil {
		return nil, fmt.Errorf("getting Cloudflare zone ID: %w", err)
	}

	cm := &CertManager{
		config: cfg,
		certManager: m,
	}

	cm.certManager.Client = &acme.Client{
		DirectoryURL: acme.LetsEncryptURL,
		ChallengeSolvers: map[string]acme.Solver{
			acme.ChallengeTypeDNS01: &cloudflareSolver{
				apiToken: cfg.CloudflareAPIToken,
				domainName: cfg.DomainName,
				api: api,
				zoneID: zoneID,
			},
		},
	}

	return cm, nil
}

func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cm.certManager.GetCertificate(hello)
}

// GetTLSConfig returns a TLS configuration that uses Let's Encrypt certificates.
func (cm *CertManager) GetTLSConfig() (*tls.Config, error) {
	if !cm.config.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		GetCertificate: cm.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
	return tlsConfig, nil
}

func (cm *CertManager) StartRenewalProcess(ctx context.Context) {
	if !cm.config.Enabled {
		return
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("Certificate renewal process stopped.")
				return
			case <-time.After(24 * time.Hour):
				log.Info().Msg("Checking certificate expiry...")
				certPath := filepath.Join(cm.config.CacheDir, cm.config.DomainName)

				cert, err := tls.LoadX509KeyPair(certPath+".crt", certPath+".key")
				if err != nil {
					log.Error().Err(err).Msg("Error loading certificate")
					continue
				}

				expiry := cert.Leaf.NotAfter
				if time.Until(expiry) < 30*24*time.Hour {
					log.Info().Msg("Certificate expiring soon, renewing...")

					//Manually trigger renewal
					_, err := cm.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: cm.config.DomainName})
					if err != nil {
						log.Error().Err(err).Msg("Error renewing certificate")
					} else {
						log.Info().Msg("Certificate renewed successfully.")
					}
				} else {
					log.Info().Msg("Certificate is valid for more than 30 days.")
				}
			}
		}
	}()
}

func (cm *CertManager) ListenAndServeTLS(ctx context.Context, hostname string, port int, handler func(net.Listener, *tls.Config) error) error {
	if !cm.config.Enabled {
		return nil
	}

	tlsConfig, err := cm.GetTLSConfig()
	if err != nil {
		return fmt.Errorf("getting TLS config: %w", err)
	}

	// Check if certs exists
	certPath := filepath.Join(cm.config.CacheDir, cm.config.DomainName)
	if _, err := os.Stat(certPath + ".crt"); errors.Is(err, os.ErrNotExist) {
		log.Info().Msg("No certificate found, requesting...")
		_, err := cm.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: cm.config.DomainName})
		if err != nil {
			log.Error().Err(err).Msg("Error getting certificate")
		}
	}

	// Listen on TCP port
	addr := fmt.Sprintf("%s:%d", hostname, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}

	return handler(listener, tlsConfig)
}


import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/almeidapaulopt/tsdproxy/internal/config"
	"github.com/cloudflare/cloudflare-go"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)


type CertManager struct {
	config config.LetsEncryptConfig
	certManager *autocert.Manager
}

func NewCertManager(cfg config.LetsEncryptConfig) (*CertManager, error) {
	cacheDir := cfg.CacheDir
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			return nil, fmt.Errorf("creating cert cache directory: %w", err)
		}
	}

	m := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			if host == cfg.DomainName {
				return nil
			}
			return fmt.Errorf("disallowed host: %s", host)
		},
	}


	api, err := cloudflare.NewWithToken(cfg.CloudflareAPIToken)
	if err != nil {
		return nil, fmt.Errorf("creating Cloudflare API client: %w", err)
	}

	// Fetch the zone ID
	zoneID, err := api.ZoneIDByName(cfg.DomainName)
	if err != nil {
		return nil, fmt.Errorf("getting Cloudflare zone ID: %w", err)
	}

	return &CertManager{
		config: cfg,
		certManager: m,
	},
}

func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cm.certManager.GetCertificate(hello)
}

// GetTLSConfig returns a TLS configuration that uses Let's Encrypt certificates.
func (cm *CertManager) GetTLSConfig() (*tls.Config, error) {
	if !cm.config.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		GetCertificate: cm.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
	return tlsConfig, nil
}

func (cm *CertManager) StartRenewalProcess(ctx context.Context) {
	if !cm.config.Enabled {
		return
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("Certificate renewal process stopped.")
				return
			case <-time.After(24 * time.Hour):
				log.Info().Msg("Checking certificate expiry...")
				certPath := filepath.Join(cm.config.CacheDir, cm.config.DomainName)

				cert, err := tls.LoadX509KeyPair(certPath+".crt", certPath+".key")
				if err != nil {
					log.Error().Err(err).Msg("Error loading certificate")
					continue
				}

				expiry := cert.Leaf.NotAfter
				if time.Until(expiry) < 30*24*time.Hour {
					log.Info().Msg("Certificate expiring soon, renewing...")

					//Manually trigger renewal
					_, err := cm.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: cm.config.DomainName})
					if err != nil {
						log.Error().Err(err).Msg("Error renewing certificate")
					} else {
						log.Info().Msg("Certificate renewed successfully.")
					}
				} else {
					log.Info().Msg("Certificate is valid for more than 30 days.")
				}
			}
		}
	}()
}

func (cm *CertManager) ListenAndServeTLS(ctx context.Context, hostname string, port int, handler func(net.Listener, *tls.Config) error) error {
	if !cm.config.Enabled {
		return nil
	}

	tlsConfig, err := cm.GetTLSConfig()
	if err != nil {
		return fmt.Errorf("getting TLS config: %w", err)
	}

	// Check if certs exists
	certPath := filepath.Join(cm.config.CacheDir, cm.config.DomainName)
	if _, err := os.Stat(certPath + ".crt"); errors.Is(err, os.ErrNotExist) {
		log.Info().Msg("No certificate found, requesting...")
		_, err := cm.certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: cm.config.DomainName})
		if err != nil {
			log.Error().Err(err).Msg("Error getting certificate")
		}
	}

	// Listen on TCP port
	addr := fmt.Sprintf("%s:%d", hostname, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}

	return handler(listener, tlsConfig)
}

	// Configure the ACME client to use the Cloudflare DNS challenge.
	cm.certManager.Client = &acme.Client{
		DirectoryURL: acme.LetsEncryptURL,
		ChallengeSolvers: map[string]acme.Solver{
			acme.ChallengeTypeDNS01: &cloudflareSolver{
				apiToken: cm.config.CloudflareAPIToken,
				domainName: cm.config.DomainName,
			},
		},
	}
	return nil
}


import (
	"context"
	"github.com/cloudflare/cloudflare-go"
)


type cloudflareSolver struct {
	apiToken string
	domainName string
	api *cloudflare.API
	zoneID string
}

func (c *cloudflareSolver) Present(ctx context.Context, challenge *acme.Challenge, domain string, value string) error {
	// Implement the logic to create a TXT record in Cloudflare DNS.
	log.Info().Str("domain", domain).Str("value", value).Msg("Creating TXT record in Cloudflare DNS")

	recordName := "_acme-challenge." + domain

	record := cloudflare.DNSRecord{Type: "TXT", Name: recordName, Content: value, TTL: 60, Proxied: cloudflare.BoolPtr(false)}

	resp, err := c.api.CreateDNSRecord(ctx, c.zoneID, record)
	if err != nil {
		log.Error().Err(err).Msg("Error creating TXT record in Cloudflare DNS")
		return err
	}

	if !resp.Success {
		log.Error().Interface("errors", resp.Errors).Msg("Error creating TXT record in Cloudflare DNS")
		return fmt.Errorf("error creating TXT record in Cloudflare DNS: %v", resp.Errors)
	}

	return nil
}

func (c *cloudflareSolver) CleanUp(ctx context.Context, challenge *acme.Challenge, domain string, value string) error {
	// Implement the logic to delete the TXT record from Cloudflare DNS.
	log.Info().Str("domain", domain).Str("value", value).Msg("Deleting TXT record from Cloudflare DNS")

	recordName := "_acme-challenge." + domain

	// Get existing DNS records
	records, _, err := c.api.DNSRecords(ctx, c.zoneID, cloudflare.DNSRecord{Type: "TXT", Name: recordName})
	if err != nil {
		log.Error().Err(err).Msg("Error getting TXT record in Cloudflare DNS")
		return err
	}


	// Delete all records with the same name
	for _, r := range records {
		resp, err := c.api.DeleteDNSRecord(ctx, c.zoneID, r.ID)
		if err != nil {
			log.Error().Err(err).Msg("Error deleting TXT record in Cloudflare DNS")
			return err
		}

		if !resp.Success {
			log.Error().Interface("errors", resp.Errors).Msg("Error deleting TXT record in Cloudflare DNS")
			return fmt.Errorf("error deleting TXT record in Cloudflare DNS: %v", resp.Errors)
		}
	}

	return nil
}