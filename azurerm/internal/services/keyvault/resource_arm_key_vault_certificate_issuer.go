package keyvault

import (
	"fmt"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/tf"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/features"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/timeouts"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func resourceArmKeyVaultCertificateIssuer() *schema.Resource {
	return &schema.Resource{
		Create: resourceArmKeyVaultCertificateIssuerCreate,
		Read:   resourceArmKeyVaultCertificateIssuerRead,
		Update: resourceArmKeyVaultCertificateIssuerUpdate,
		Delete: resourceArmKeyVaultCertificateIssuerDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(30 * time.Minute),
			Delete: schema.DefaultTimeout(30 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: azure.ValidateKeyVaultChildName,
			},

			"key_vault_id": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: azure.ValidateResourceID,
			},

			"provider_name": {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: false,
			},
		},
	}
}

func resourceArmKeyVaultCertificateIssuerCreate(d *schema.ResourceData, meta interface{}) error {
	vaultClient := meta.(*clients.Client).KeyVault.VaultsClient
	client := meta.(*clients.Client).KeyVault.ManagementClient
	ctx, cancel := timeouts.ForCreate(meta.(*clients.Client).StopContext, d)
	defer cancel()

	log.Print("[INFO] preparing arguments for AzureRM KeyVault CertificateIssuer creation.")

	name := d.Get("name").(string)
	keyVaultId := d.Get("key_vault_id").(string)

	keyVaultBaseUrl, err := azure.GetKeyVaultBaseUrlFromID(ctx, vaultClient, keyVaultId)
	if err != nil {
		return fmt.Errorf("Error looking up CertificateIssuer %q vault url from id %q: %+v", name, keyVaultId, err)
	}

	if features.ShouldResourcesBeImported() {
		existing, err := client.GetCertificateIssuer(ctx, keyVaultBaseUrl, name)
		if err != nil {
			if !utils.ResponseWasNotFound(existing.Response) {
				return fmt.Errorf("Error checking for presence of existing CertificateIssuer %q (Key Vault %q): %s", name, keyVaultBaseUrl, err)
			}
		}

		if existing.ID != nil && *existing.ID != "" {
			return tf.ImportAsExistsError("azurerm_key_vault_certificate_issuer", *existing.ID)
		}
	}

	provider := d.Get("provider_name").(string)

	parameters := keyvault.CertificateIssuerSetParameters{
		Provider: utils.String(provider),
	}

	if _, err := client.SetCertificateIssuer(ctx, keyVaultBaseUrl, name, parameters); err != nil {
		return err
	}

	// "" indicates the latest version
	read, err := client.GetCertificateIssuer(ctx, keyVaultBaseUrl, name)
	if err != nil {
		return err
	}
	if read.ID == nil {
		return fmt.Errorf("Cannot read KeyVault Issuer '%s' (in key vault '%s')", name, keyVaultBaseUrl)
	}

	d.SetId(*read.ID)

	return resourceArmKeyVaultCertificateIssuerRead(d, meta)
}

func resourceArmKeyVaultCertificateIssuerUpdate(d *schema.ResourceData, meta interface{}) error {
	keyVaultClient := meta.(*clients.Client).KeyVault.VaultsClient
	client := meta.(*clients.Client).KeyVault.ManagementClient
	ctx, cancel := timeouts.ForUpdate(meta.(*clients.Client).StopContext, d)
	defer cancel()
	log.Print("[INFO] preparing arguments for AzureRM KeyVault CertificateIssuer update.")

	name := d.Get("name").(string)
	keyVaultId := d.Get("key_vault_id").(string)
	keyVaultBaseUrl, err := azure.GetKeyVaultBaseUrlFromID(ctx, keyVaultClient, keyVaultId)

	if err != nil {
		return err
	}

	ok, err := azure.KeyVaultExists(ctx, keyVaultClient, keyVaultId)
	if err != nil {
		return fmt.Errorf("Error checking if key vault %q for CertificateIssuer %q in Vault at url %q exists: %v", keyVaultId, name, keyVaultBaseUrl, err)
	}
	if !ok {
		log.Printf("[DEBUG] CertificateIssuer %q Key Vault %q was not found in Key Vault at URI %q - removing from state", name, keyVaultId, keyVaultBaseUrl)
		d.SetId("")
		return nil
	}

	provider := d.Get("provider_name").(string)

	if d.HasChange("value") {
		// for changing the value of the CertificateIssuer we need to create a new version
		parameters := keyvault.CertificateIssuerSetParameters{
			Provider: utils.String(provider),
		}

		if _, err = client.SetCertificateIssuer(ctx, keyVaultBaseUrl, name, parameters); err != nil {
			return err
		}

		// "" indicates the latest version
		read, err2 := client.GetCertificateIssuer(ctx, keyVaultBaseUrl, name)
		if err2 != nil {
			return fmt.Errorf("Error getting Key Vault CertificateIssuer %q : %+v", name, err2)
		}

		if _, err = azure.ParseKeyVaultChildID(*read.ID); err != nil {
			return err
		}

		// the ID is suffixed with the CertificateIssuer version
		d.SetId(*read.ID)
	} else {
		parameters := keyvault.CertificateIssuerUpdateParameters{
			Provider: utils.String(provider),
		}

		if _, err = client.UpdateCertificateIssuer(ctx, keyVaultBaseUrl, name, parameters); err != nil {
			return err
		}
	}

	return resourceArmKeyVaultCertificateIssuerRead(d, meta)
}

func resourceArmKeyVaultCertificateIssuerRead(d *schema.ResourceData, meta interface{}) error {
	keyVaultClient := meta.(*clients.Client).KeyVault.VaultsClient
	client := meta.(*clients.Client).KeyVault.ManagementClient
	ctx, cancel := timeouts.ForRead(meta.(*clients.Client).StopContext, d)
	defer cancel()

	name := d.Get("name").(string)
	keyVaultId := d.Get("key_vault_id").(string)
	keyVaultBaseUrl, err := azure.GetKeyVaultBaseUrlFromID(ctx, keyVaultClient, keyVaultId)

	ok, err := azure.KeyVaultExists(ctx, keyVaultClient, keyVaultId)
	if err != nil {
		return fmt.Errorf("Error checking if key vault %q for CertificateIssuer %q in Vault at url %q exists: %v", keyVaultId, name, keyVaultBaseUrl, err)
	}
	if !ok {
		log.Printf("[DEBUG] CertificateIssuer %q Key Vault %q was not found in Key Vault at URI %q - removing from state", name, keyVaultId, keyVaultBaseUrl)
		d.SetId("")
		return nil
	}

	// we always want to get the latest version
	resp, err := client.GetCertificateIssuer(ctx, keyVaultBaseUrl, name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			log.Printf("[DEBUG] CertificateIssuer %q was not found in Key Vault at URI %q - removing from state", name, keyVaultBaseUrl)
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Error making Read request on Azure KeyVault CertificateIssuer %s: %+v", name, err)
	}

	d.Set("name", name)
	d.Set("provider_name", resp.Provider)

	return nil
}

func resourceArmKeyVaultCertificateIssuerDelete(d *schema.ResourceData, meta interface{}) error {
	keyVaultClient := meta.(*clients.Client).KeyVault.VaultsClient
	client := meta.(*clients.Client).KeyVault.ManagementClient
	ctx, cancel := timeouts.ForDelete(meta.(*clients.Client).StopContext, d)
	defer cancel()

	name := d.Get("name").(string)
	keyVaultId := d.Get("key_vault_id").(string)
	keyVaultBaseUrl, err := azure.GetKeyVaultBaseUrlFromID(ctx, keyVaultClient, keyVaultId)

	ok, err := azure.KeyVaultExists(ctx, keyVaultClient, keyVaultId)
	if err != nil {
		return fmt.Errorf("Error checking if key vault %q for CertificateIssuer %q in Vault at url %q exists: %v", keyVaultId, name, keyVaultBaseUrl, err)
	}
	if !ok {
		log.Printf("[DEBUG] CertificateIssuer %q Key Vault %q was not found in Key Vault at URI %q - removing from state", name, keyVaultId, keyVaultBaseUrl)
		d.SetId("")
		return nil
	}

	_, err = client.DeleteCertificateIssuer(ctx, keyVaultBaseUrl, name)
	return err
}
