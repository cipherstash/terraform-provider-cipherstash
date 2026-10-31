package provider

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	control "github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage"
	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6/tf6server"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

const cliProvider = `
provider "cipherstash" {
  workspace_crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"
  client_access_key = "CSAKtestKeyId.testKeySecret"
}
`

func cliTestCase(t *testing.T, f *serviceFixture) resource.TestCase {
	t.Helper()
	// Never let plugin-testing download a different Terraform or use a user's
	// CLI configuration. The provider runs in-process; only Terraform is a child.
	binary, err := exec.LookPath("terraform")
	require.NoError(t, err, "Terraform 1.14.6 is required; run through mise")
	t.Setenv("CHECKPOINT_DISABLE", "1")
	tf, err := tfexec.NewTerraform(t.TempDir(), binary)
	require.NoError(t, err)
	version, _, err := tf.Version(t.Context(), false)
	require.NoError(t, err, "Terraform version")
	require.Equal(t, "1.14.6", version.String())
	t.Setenv("TF_ACC_TERRAFORM_PATH", binary)
	t.Setenv("TF_ACC", "")
	t.Setenv("TF_CLI_ARGS", "")
	t.Setenv("TF_CLI_ARGS_plan", "")
	t.Setenv("TF_CLI_ARGS_apply", "")
	config := filepath.Join(t.TempDir(), "terraform.rc")
	require.NoError(t, os.WriteFile(config, nil, 0o600))
	t.Setenv("TF_CLI_CONFIG_FILE", config)
	rt := fixtureTransport(t, "admin", f.ServeHTTP)
	previous := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() { http.DefaultTransport = previous })

	return resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cipherstash": func() (tfprotov6.ProviderServer, error) {
				p := New()
				t.Cleanup(p.Close)

				return Protocol6(p), nil
			},
		},
		CheckDestroy: func(*terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			if len(f.actors) != 0 || len(f.keys) != 0 || len(f.clients) != 0 {
				return fmt.Errorf("destroy left owned actors, access keys or clients")
			}

			for _, k := range f.keysets {
				if k.ID != keysetID && k.ID != tenantKeysetID && !k.IsDisabled {
					return fmt.Errorf("destroy left created keyset %s enabled", k.ID)
				}
			}

			return nil
		},
	}
}

func TestCLIActorClientLifecycle(t *testing.T) {
	f := newServiceFixture(t)
	tc := cliTestCase(t, f)
	configuration := func(name string) string {
		return cliProvider + fmt.Sprintf(`
resource "cipherstash_cts_actor" "api" {
  name = %q
  kind = "agent"
  role = "control"
  token_expiry = 1234
}
resource "cipherstash_zerokms_client" "api" {
  name = %q
  description = "API encryption"
}
data "cipherstash_zerokms_client" "api" { id = cipherstash_zerokms_client.api.id }
`, name, name)
	}
	var originalActor, originalClient, actorSecret, clientSecret string
	check := func(replaced bool) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			a := s.RootModule().Resources["cipherstash_cts_actor.api"].Primary
			c := s.RootModule().Resources["cipherstash_zerokms_client.api"].Primary
			d := s.RootModule().Resources["data.cipherstash_zerokms_client.api"].Primary
			if a.ID == "" || c.ID == "" || a.Attributes["access_key"] != f.secrets[a.ID] || c.Attributes["client_key"] != f.secrets[c.ID] {
				return fmt.Errorf("state did not preserve fixture-issued identities and secrets")
			}

			if d.ID != c.ID || d.Attributes["name"] != c.Attributes["name"] || d.Attributes["keyset_ids.#"] != "1" {
				return fmt.Errorf("dependent lookup did not resolve the created client")
			}

			if originalActor == "" {
				originalActor, originalClient = a.ID, c.ID
				actorSecret, clientSecret = a.Attributes["access_key"], c.Attributes["client_key"]
			} else if replaced {
				if a.ID == originalActor || c.ID == originalClient || a.Attributes["access_key"] == actorSecret || c.Attributes["client_key"] == clientSecret {
					return fmt.Errorf("replacement reused an identity or secret")
				}
			} else if a.ID != originalActor || c.ID != originalClient || a.Attributes["access_key"] != actorSecret || c.Attributes["client_key"] != clientSecret {
				return fmt.Errorf("refresh changed identities or secrets")
			}

			return nil
		}
	}
	tc.Steps = []resource.TestStep{
		{Config: configuration("api"), Check: check(false), ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectSensitiveValue("cipherstash_cts_actor.api", tfjsonpath.New("access_key")),
			statecheck.ExpectSensitiveValue("cipherstash_zerokms_client.api", tfjsonpath.New("client_key")),
		}},
		{Config: configuration("api"), Check: check(false), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{Config: configuration("api-v2"), Check: check(true), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction("cipherstash_cts_actor.api", plancheck.ResourceActionDestroyBeforeCreate),
			plancheck.ExpectResourceAction("cipherstash_zerokms_client.api", plancheck.ResourceActionDestroyBeforeCreate),
		}}},
	}
	resource.UnitTest(t, tc)
}

func TestCLIKeysetLifecycle(t *testing.T) {
	for _, initiallyEnabled := range []bool{true, false} {
		t.Run(fmt.Sprint(initiallyEnabled), func(t *testing.T) {
			f := newServiceFixture(t)
			tc := cliTestCase(t, f)
			configuration := func(description string, enabled bool) string {
				return cliProvider + fmt.Sprintf(`
resource "cipherstash_zerokms_keyset" "app" {
  name = "application-%s"
  description = %q
  enabled = %t
}
`, description, description, enabled)
			}
			var id string
			check := func(enabled bool, description string) resource.TestCheckFunc {
				return func(s *terraform.State) error {
					f.mu.Lock()
					defer f.mu.Unlock()

					current := s.RootModule().Resources["cipherstash_zerokms_keyset.app"].Primary.ID
					if id != "" && id != current {
						return fmt.Errorf("keyset update replaced identity")
					}

					id = current
					i := slices.IndexFunc(f.keysets, func(k control.ZeroKMSKeyset) bool { return k.ID == id })
					if i < 0 || f.keysets[i].IsDisabled == enabled || f.keysets[i].Description != description || f.keysets[i].Name != "application-"+description {
						return fmt.Errorf("keyset inventory does not match configuration")
					}

					return nil
				}
			}
			tc.Steps = []resource.TestStep{
				{Config: configuration("initial", initiallyEnabled), Check: check(initiallyEnabled, "initial")},
				{Config: configuration("updated", !initiallyEnabled), Check: check(!initiallyEnabled, "updated"), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("cipherstash_zerokms_keyset.app", plancheck.ResourceActionUpdate)}}},
				{Config: configuration("updated", initiallyEnabled), Check: check(initiallyEnabled, "updated")},
			}
			// A disabled keyset must never be enabled implicitly to edit metadata.
			var writes int
			disabled := configuration("updated", false)
			tc.Steps = append(tc.Steps,
				resource.TestStep{Config: disabled, Check: check(false, "updated")},
				resource.TestStep{PreConfig: func() { f.edit(func() { writes = len(f.mutations) }) }, Config: strings.Replace(disabled, `name = "application-updated"`, `name = "renamed"`, 1), PlanOnly: true, ExpectError: regexp.MustCompile("Cannot modify disabled keyset")},
				resource.TestStep{Config: strings.Replace(disabled, `description = "updated"`, `description = "edited"`, 1), PlanOnly: true, ExpectError: regexp.MustCompile("Cannot modify disabled keyset")},
				resource.TestStep{PreConfig: func() {
					f.edit(func() { require.Len(t, f.mutations, writes, "rejected metadata changes wrote to CipherStash") })
				}, Config: disabled, Check: check(false, "updated"), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			)
			resource.UnitTest(t, tc)
			f.edit(func() {
				assert.Len(t, f.keysets, 3, "destroy removed key material")
			})
		})
	}
}

func TestCLIGrantOwnership(t *testing.T) {
	f := newServiceFixture(t)
	tc := cliTestCase(t, f)
	base := cliProvider + `
resource "cipherstash_zerokms_client" "api" {
  name = "api"
  description = "application client"
}
resource "cipherstash_zerokms_keyset" "app" {
  name = "application"
  description = "application keyset"
}
`
	grant := func(expression string) string {
		return base + fmt.Sprintf(`
resource "cipherstash_zerokms_keyset_grant" "app" {
  client_id = cipherstash_zerokms_client.api.id
  keyset_id = %s
}
`, expression)
	}
	check := func(want int) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			if len(f.clients) != 1 || len(f.clients[0].KeysetIDs) != want || !slices.Contains(f.clients[0].KeysetIDs, keysetID) {
				return fmt.Errorf("grant operation changed the default or unrelated grants: %+v", f.clients)
			}

			if g := s.RootModule().Resources["cipherstash_zerokms_keyset_grant.app"]; g != nil {
				if !slices.Contains(f.clients[0].KeysetIDs, g.Primary.Attributes["keyset_id"]) || g.Primary.ID != f.clients[0].ID+"/"+g.Primary.Attributes["keyset_id"] {
					return fmt.Errorf("grant state does not identify the owned pair")
				}
			}

			return nil
		}
	}
	tc.Steps = []resource.TestStep{
		{Config: grant("cipherstash_zerokms_keyset.app.id"), Check: check(2)},
		{Config: grant(fmt.Sprintf("%q", tenantKeysetID)), Check: check(2), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction("cipherstash_zerokms_keyset_grant.app", plancheck.ResourceActionDestroyBeforeCreate),
			plancheck.ExpectResourceAction("cipherstash_zerokms_client.api", plancheck.ResourceActionNoop),
		}}},
		{PreConfig: func() {
			f.edit(func() { f.clients[0].KeysetIDs = append(f.clients[0].KeysetIDs, f.keysets[2].ID) })
		}, Config: base, Check: func(s *terraform.State) error {
			if err := check(2)(s); err != nil {
				return err
			}

			f.mu.Lock()
			defer f.mu.Unlock()

			if slices.Contains(f.clients[0].KeysetIDs, tenantKeysetID) || !slices.Contains(f.clients[0].KeysetIDs, f.keysets[2].ID) {
				return fmt.Errorf("revocation did not preserve the externally added grant")
			}

			return nil
		}},
		{Config: grant("cipherstash_zerokms_client.api.keyset_id"), ExpectError: regexp.MustCompile("Grant already exists")},
		{Config: base, Check: check(2), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{
			Config: grant(fmt.Sprintf("%q", keysetID)), ResourceName: "cipherstash_zerokms_keyset_grant.app", ImportState: true, ImportStatePersist: true,
			ImportStateIdFunc: func(s *terraform.State) (string, error) {
				return s.RootModule().Resources["cipherstash_zerokms_client.api"].Primary.ID + "/" + keysetID, nil
			},
		},
		{Config: grant(fmt.Sprintf("%q", keysetID)), Check: check(2), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{Config: base, Check: func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			client := s.RootModule().Resources["cipherstash_zerokms_client.api"].Primary
			if len(f.clients) != 1 || client.ID != f.clients[0].ID || client.Attributes["client_key"] != f.secrets[client.ID] || client.Attributes["keyset_id"] != keysetID || !slices.Equal(f.clients[0].KeysetIDs, []string{f.keysets[2].ID}) {
				return fmt.Errorf("revoking the imported default grant changed the client or an unrelated grant")
			}

			return nil
		}},
		{Config: base, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
	}
	resource.UnitTest(t, tc)
}

func TestCLIImports(t *testing.T) {
	for _, kind := range []string{"actor", "client", "client-zero-grants", "client-many-grants", "client-legacy-pair", "client-legacy-absent-grant", "keyset", "keyset_grant"} {
		t.Run(kind, func(t *testing.T) {
			f := newServiceFixture(t)
			tc := cliTestCase(t, f)
			var address, id, config string
			var checks []statecheck.StateCheck
			var rejected []resource.TestStep
			switch kind {
			case "actor":
				id, address = "app-imported", "cipherstash_cts_actor.app"
				f.actors = []control.CTSActor{{ID: id, Name: "imported", Kind: "app", CreatedAt: fixtureTimestamp}}
				f.keys = []control.CTSAccessKeyMetadata{{ID: "key-" + id, Name: "imported", Role: "member", CreatedAt: fixtureTimestamp}}
				config = `resource "cipherstash_cts_actor" "app" { name = "imported" }`
				checks = []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("access_key"), knownvalue.Null()),
					statecheck.ExpectKnownValue(address, tfjsonpath.New("token_expiry"), knownvalue.Null()),
				}
			case "client", "client-zero-grants", "client-many-grants", "client-legacy-pair", "client-legacy-absent-grant":
				id, address = clientID, "cipherstash_zerokms_client.app"
				f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID}}}
				config = "resource \"cipherstash_zerokms_client\" \"app\" {\n name = \"imported\"\n description = \"existing\"\n}"
				var historical knownvalue.Check = knownvalue.Null()
				switch kind {
				case "client-zero-grants", "client-legacy-absent-grant":
					f.clients[0].KeysetIDs = []string{}
				case "client-many-grants", "client-legacy-pair":
					f.clients[0].KeysetIDs = append(f.clients[0].KeysetIDs, tenantKeysetID)
				}

				if kind == "client-legacy-pair" || kind == "client-legacy-absent-grant" {
					id += "/" + tenantKeysetID
					historical = knownvalue.StringExact(tenantKeysetID)
				}

				rejected = []resource.TestStep{{
					PreConfig: func() { f.edit(func() { f.faults = []serviceFault{{path: "/list-clients", status: 500}} }) },
					Config:    cliProvider + config, ResourceName: address, ImportState: true, ImportStatePersist: true, ImportStateId: id,
					ExpectError: regexp.MustCompile("Cannot import client"),
				}}

				checks = []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("client_key"), knownvalue.Null()),
					statecheck.ExpectKnownValue(address, tfjsonpath.New("keyset_id"), historical),
				}
			case "keyset":
				id, address = tenantKeysetID, "cipherstash_zerokms_keyset.app"
				f.keysets[1].IsDisabled = true
				config = "resource \"cipherstash_zerokms_keyset\" \"app\" {\n name = \"external\"\n description = \"Worker owned\"\n enabled = false\n}"
				checks = []statecheck.StateCheck{statecheck.ExpectKnownValue(address, tfjsonpath.New("enabled"), knownvalue.Bool(false))}
			case "keyset_grant":
				id, address = clientID+"/"+tenantKeysetID, "cipherstash_zerokms_keyset_grant.app"
				f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "external", KeysetIDs: []string{keysetID, tenantKeysetID}}}
				config = fmt.Sprintf("resource \"cipherstash_zerokms_keyset_grant\" \"app\" {\n client_id = %q\n keyset_id = %q\n}", clientID, tenantKeysetID)
				tc.CheckDestroy = func(*terraform.State) error {
					f.mu.Lock()
					defer f.mu.Unlock()

					if len(f.clients) != 1 || !slices.Equal(f.clients[0].KeysetIDs, []string{keysetID}) {
						return fmt.Errorf("destroy changed more than the imported pair")
					}

					return nil
				}
			}

			tc.Steps = []resource.TestStep{{Config: cliProvider}}
			tc.Steps = append(tc.Steps, rejected...)
			tc.Steps = append(tc.Steps,
				resource.TestStep{Config: cliProvider + config, ResourceName: address, ImportState: true, ImportStatePersist: true, ImportStateId: id},
				resource.TestStep{Config: cliProvider + config, ConfigStateChecks: checks, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}, Check: func(*terraform.State) error {
					f.mu.Lock()
					defer f.mu.Unlock()

					if len(f.mutations) != 0 {
						return fmt.Errorf("import or subsequent apply mutated inventory: %v", f.mutations)
					}

					return nil
				}},
			)
			resource.UnitTest(t, tc)
		})
	}
}

// ExpectError stops a failed-apply step before state checks run. Inspect the next
// real plan instead: its Before values include both current and deposed objects.
type persistedActorsPlan struct {
	fixture *serviceFixture
	count   int
}

func (check persistedActorsPlan) CheckPlan(_ context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	f := check.fixture
	f.mu.Lock()
	defer f.mu.Unlock()

	seen := map[string]bool{}
	for _, change := range req.Plan.ResourceChanges {
		if change.Address != "cipherstash_cts_actor.app" {
			continue
		}

		before, ok := change.Change.Before.(map[string]any)
		if !ok {
			resp.Error = fmt.Errorf("failed creation was forgotten by Terraform")
			return
		}

		id, _ := before["id"].(string)
		if id == "" || seen[id] || before["access_key"] != f.secrets[id] || f.secrets[id] == "" {
			resp.Error = fmt.Errorf("failed apply did not persist distinct identities and their one-time secrets")
			return
		}

		seen[id] = true
		if (change.DeposedKey == "" && !change.Change.Actions.Replace()) || (change.DeposedKey != "" && !change.Change.Actions.Delete()) {
			resp.Error = fmt.Errorf("recovery did not plan replacement and deposed cleanup: %v", change.Change.Actions)
			return
		}
	}

	if len(seen) != check.count || len(f.actors) != check.count {
		resp.Error = fmt.Errorf("recovery plan contains %d actors; inventory contains %d; expected %d", len(seen), len(f.actors), check.count)
		return
	}

	for _, actor := range f.actors {
		if !seen[actor.ID] {
			resp.Error = fmt.Errorf("actor %s was orphaned by the failed apply", actor.ID)
		}
	}
}

func TestCLIFailedCreateRecovery(t *testing.T) {
	testCLIActorRecovery(t, false)
}

func TestCLIFailedReplacementRecovery(t *testing.T) {
	testCLIActorRecovery(t, true)
}

func testCLIActorRecovery(t *testing.T, replacement bool) {
	t.Helper()
	f := newServiceFixture(t)
	tc := cliTestCase(t, f)
	config := func(name string) string {
		lifecycle := ""
		if replacement {
			lifecycle = "lifecycle { create_before_destroy = true }"
		}

		return cliProvider + fmt.Sprintf("resource \"cipherstash_cts_actor\" \"app\" {\n name = %q\n %s\n}", name, lifecycle)
	}
	count := 1
	if replacement {
		tc.Steps = append(tc.Steps, resource.TestStep{Config: config("original")})
		count = 2
	}

	tc.Steps = append(tc.Steps,
		resource.TestStep{PreConfig: func() { f.edit(func() { f.failActorMetadata = true }) }, Config: config("partial"), ExpectError: regexp.MustCompile("Cannot read actor after creation")},
		resource.TestStep{Config: config("recovered"), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{persistedActorsPlan{fixture: f, count: count}}}, Check: func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			state := s.RootModule().Resources["cipherstash_cts_actor.app"].Primary
			if len(f.actors) != 1 || f.actors[0].ID != state.ID || f.actors[0].Name != "recovered" || state.Attributes["access_key"] != f.secrets[state.ID] {
				return fmt.Errorf("recovery left an orphan or lost the replacement secret")
			}

			return nil
		}},
		resource.TestStep{Config: config("recovered"), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
	)
	resource.UnitTest(t, tc)
}

func TestCLIExternalDrift(t *testing.T) {
	t.Run("missing objects and changed metadata", func(t *testing.T) {
		f := newServiceFixture(t)
		tc := cliTestCase(t, f)
		config := cliProvider + `
resource "cipherstash_cts_actor" "app" { name = "app" }
resource "cipherstash_zerokms_client" "app" {
  name = "app"
  description = "application"
}
resource "cipherstash_zerokms_keyset" "app" {
  name = "application"
  description = "owned metadata"
}
resource "cipherstash_zerokms_keyset_grant" "app" {
  client_id = cipherstash_zerokms_client.app.id
  keyset_id = cipherstash_zerokms_keyset.app.id
}
`
		var oldActor, oldClient, oldKeyset string
		tc.Steps = []resource.TestStep{
			{Config: config, Check: func(s *terraform.State) error {
				oldActor = s.RootModule().Resources["cipherstash_cts_actor.app"].Primary.ID
				oldClient = s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary.ID
				oldKeyset = s.RootModule().Resources["cipherstash_zerokms_keyset.app"].Primary.ID

				return nil
			}},
			{PreConfig: func() {
				f.edit(func() {
					f.actors, f.keys, f.clients = nil, nil, nil
					f.keysets[2].Description = "external edit"
					f.keysets[2].IsDisabled = true
				})
			}, Config: config, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("cipherstash_cts_actor.app", plancheck.ResourceActionCreate),
				plancheck.ExpectResourceAction("cipherstash_zerokms_client.app", plancheck.ResourceActionCreate),
				plancheck.ExpectResourceAction("cipherstash_zerokms_keyset.app", plancheck.ResourceActionUpdate),
				plancheck.ExpectResourceAction("cipherstash_zerokms_keyset_grant.app", plancheck.ResourceActionCreate),
			}}, Check: func(s *terraform.State) error {
				f.mu.Lock()
				defer f.mu.Unlock()

				if s.RootModule().Resources["cipherstash_cts_actor.app"].Primary.ID == oldActor || s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary.ID == oldClient || s.RootModule().Resources["cipherstash_zerokms_keyset.app"].Primary.ID != oldKeyset {
					return fmt.Errorf("drift recovery recreated the wrong identities")
				}

				if len(f.actors) != 1 || len(f.clients) != 1 || f.keysets[2].IsDisabled || f.keysets[2].Description != "owned metadata" || !slices.Contains(f.clients[0].KeysetIDs, oldKeyset) {
					return fmt.Errorf("drift recovery did not restore the configured inventory")
				}

				return nil
			}},
		}
		resource.UnitTest(t, tc)
	})
	t.Run("external grants and historical state", func(t *testing.T) {
		f := newServiceFixture(t)
		tc := cliTestCase(t, f)
		config := cliProvider + "resource \"cipherstash_zerokms_client\" \"app\" {\n name = \"app\"\n description = \"application\"\n}"
		var id, secret string
		check := func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			client := s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary
			if client.ID != id || client.Attributes["client_key"] != secret || client.Attributes["keyset_id"] != keysetID || len(f.mutations) != 1 {
				return fmt.Errorf("refresh changed client identity, creation secret, historical keyset or grants")
			}

			return nil
		}
		tc.Steps = []resource.TestStep{
			{Config: config, Check: func(s *terraform.State) error {
				client := s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary
				id, secret = client.ID, client.Attributes["client_key"]

				return nil
			}},
			{PreConfig: func() { f.edit(func() { f.clients[0].KeysetIDs = append(f.clients[0].KeysetIDs, tenantKeysetID) }) }, Config: config, Check: check, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			{PreConfig: func() { f.edit(func() { f.clients[0].KeysetIDs = []string{tenantKeysetID} }) }, Config: config, Check: check, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			{PreConfig: func() { f.edit(func() { f.clients[0].KeysetIDs = []string{} }) }, Config: config, Check: check, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			{PreConfig: func() { f.edit(func() { f.faults = []serviceFault{{path: "/list-clients", status: 500}} }) }, Config: config, ExpectError: regexp.MustCompile("Cannot read client")},
			{Config: config, Check: check, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		}
		resource.UnitTest(t, tc)
	})
}

func TestCLIMalformedInventoryRecovery(t *testing.T) {
	f := newServiceFixture(t)
	tc := cliTestCase(t, f)
	config := cliProvider + "resource \"cipherstash_zerokms_client\" \"app\" {\n name = \"app\"\n description = \"application\"\n}"
	var id, secret string
	check := func(s *terraform.State) error {
		client := s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary
		if client.ID != id || client.Attributes["client_key"] != secret || client.Attributes["name"] != "app" || client.Attributes["description"] != "application" {
			return fmt.Errorf("failed refresh changed the client's identity, metadata or secret")
		}

		f.edit(func() { require.Empty(t, f.mutations, "failed refresh or recovery mutated the service") })

		return nil
	}
	tc.Steps = []resource.TestStep{{Config: config, Check: func(s *terraform.State) error {
		client := s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary
		id, secret = client.ID, client.Attributes["client_key"]

		return nil
	}}}
	for _, malformed := range []string{"invalid UUID", "duplicate ID", "missing description", "null description"} {
		tc.Steps = append(tc.Steps, resource.TestStep{
			PreConfig: func() {
				body := fmt.Sprintf(`[{"id":%q,"name":"app","description":"application","keyset_id":[%q]}]`, id, keysetID)
				switch malformed {
				case "invalid UUID":
					body = strings.Replace(body, id, "invalid-id", 1)
				case "duplicate ID":
					body = strings.Replace(body, `"id":`, fmt.Sprintf(`"id":%q,"id":`, tenantKeysetID), 1)
				case "missing description":
					body = strings.Replace(body, `,"description":"application"`, "", 1)
				case "null description":
					body = strings.Replace(body, `"description":"application"`, `"description":null`, 1)
				}

				f.edit(func() {
					f.mutations = nil
					f.faults = []serviceFault{{path: "/list-clients", status: 200, body: body}}
				})
			}, Config: config, PlanOnly: true, ExpectError: regexp.MustCompile("Cannot read client"),
		}, resource.TestStep{
			Config: config, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}, Check: check,
		})
	}

	resource.UnitTest(t, tc)
}

func TestCLIProviderConfiguration(t *testing.T) {
	for _, test := range []struct{ name, config, error string }{
		{"omitted uses environment", `provider "cipherstash" {}`, ""},
		{"null uses environment", "provider \"cipherstash\" {\n workspace_crn = null\n client_access_key = null\n}", ""},
		{"explicit overrides environment", cliProvider, ""},
		{"empty crn", `provider "cipherstash" { workspace_crn = "" }`, "Workspace CRN required"},
		{"empty key", `provider "cipherstash" { client_access_key = "" }`, "Client access key required"},
		{"malformed crn", `provider "cipherstash" { workspace_crn = "invalid" }`, "Invalid workspace CRN"},
		{"malformed key", `provider "cipherstash" { client_access_key = "invalid" }`, "Invalid access key"},
		{"old crn argument", `provider "cipherstash" { crn = "invalid" }`, "Unsupported argument"},
		{"old control key argument", `provider "cipherstash" { control_access_key = "CSAKlegacy.secret" }`, "Unsupported argument"},
		{"old access key argument", `provider "cipherstash" { access_key = "CSAKlegacy.secret" }`, "Unsupported argument"},
		{"legacy control environment", `provider "cipherstash" {}`, "Client access key required"},
		{"legacy cipherstash environment", `provider "cipherstash" {}`, "Client access key required"},
		{"malformed environment crn", `provider "cipherstash" {}`, "Invalid workspace CRN"},
		{"malformed environment key", `provider "cipherstash" {}`, "Invalid access key"},
		{"control credential", `provider "cipherstash" {}`, "Cannot authenticate with CipherStash"},
		{"member credential", `provider "cipherstash" {}`, "Cannot authenticate with CipherStash"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("CS_WORKSPACE_CRN", testCRN)
			t.Setenv("CS_CLIENT_ACCESS_KEY", "CSAKtestKeyId.testKeySecret")
			t.Setenv("CS_CONTROL_ACCESS_KEY", "")
			t.Setenv("CIPHERSTASH_ACCESS_KEY", "")
			switch test.name {
			case "explicit overrides environment":
				t.Setenv("CS_WORKSPACE_CRN", "invalid-environment-crn")
				t.Setenv("CS_CLIENT_ACCESS_KEY", "invalid-environment-key")
			case "legacy control environment":
				t.Setenv("CS_CLIENT_ACCESS_KEY", "")
				t.Setenv("CS_CONTROL_ACCESS_KEY", "CSAKlegacy.secret")
			case "legacy cipherstash environment":
				t.Setenv("CS_CLIENT_ACCESS_KEY", "")
				t.Setenv("CIPHERSTASH_ACCESS_KEY", "CSAKlegacy.secret")
			case "malformed environment crn":
				t.Setenv("CS_WORKSPACE_CRN", "invalid-environment-crn")
			case "malformed environment key":
				t.Setenv("CS_CLIENT_ACCESS_KEY", "invalid-environment-key")
				t.Setenv("CS_CONTROL_ACCESS_KEY", "CSAKlegacy.secret")
				t.Setenv("CIPHERSTASH_ACCESS_KEY", "CSAKlegacy.secret")
			}

			f := newServiceFixture(t)
			f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "existing", KeysetIDs: []string{}}}
			var rejectedTransport http.RoundTripper
			switch test.name {
			case "control credential":
				rejectedTransport = fixtureTransport(t, "control", f.ServeHTTP)
			case "member credential":
				rejectedTransport = fixtureTransport(t, "member", f.ServeHTTP)
			}

			tc := cliTestCase(t, f)
			if rejectedTransport != nil {
				// cliTestCase restores the process-default transport during cleanup.
				http.DefaultTransport = rejectedTransport
			}

			tc.CheckDestroy = func(*terraform.State) error {
				f.mu.Lock()
				defer f.mu.Unlock()

				if len(f.clients) != 1 || f.clients[0].ID != clientID || len(f.mutations) != 0 {
					return fmt.Errorf("data source changed existing inventory")
				}

				return nil
			}
			step := resource.TestStep{
				Config:            test.config + fmt.Sprintf("\ndata \"cipherstash_zerokms_client\" \"app\" { id = %q }", clientID),
				ConfigStateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue("data.cipherstash_zerokms_client.app", tfjsonpath.New("name"), knownvalue.StringExact("existing"))},
			}
			if test.error != "" {
				step.ExpectError = regexp.MustCompile(test.error)
				step.ConfigStateChecks = nil
			}

			tc.Steps = []resource.TestStep{step}
			resource.UnitTest(t, tc)
			f.edit(func() {
				assert.Empty(t, f.mutations, "provider configuration changed inventory")
				if rejectedTransport != nil {
					assert.Empty(t, f.requests, "non-Admin credential reached management API")
				}
			})
		})
	}
}

func TestCLIValidation(t *testing.T) {
	for _, expiry := range []int64{1, 86400} {
		t.Run(fmt.Sprintf("valid token lifetime %d", expiry), func(t *testing.T) {
			f := newServiceFixture(t)
			tc := cliTestCase(t, f)
			tc.Steps = []resource.TestStep{{
				Config:            cliProvider + fmt.Sprintf("resource \"cipherstash_cts_actor\" \"app\" {\n name = \"app\"\n token_expiry = %d\n}", expiry),
				ConfigStateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue("cipherstash_cts_actor.app", tfjsonpath.New("token_expiry"), knownvalue.Int64Exact(expiry))},
			}}
			resource.UnitTest(t, tc)
		})
	}

	for _, test := range []struct{ name, config, error string }{
		{"actor kind", "resource \"cipherstash_cts_actor\" \"app\" {\n name = \"app\"\n kind = \"human\"\n}", "Invalid Attribute Value Match"},
		{"actor role", "resource \"cipherstash_cts_actor\" \"app\" {\n name = \"app\"\n role = \"owner\"\n}", "Invalid Attribute Value Match"},
		{"token below minimum", "resource \"cipherstash_cts_actor\" \"app\" {\n name = \"app\"\n token_expiry = 0\n}", "Invalid Attribute Value"},
		{"token above maximum", "resource \"cipherstash_cts_actor\" \"app\" {\n name = \"app\"\n token_expiry = 86401\n}", "Invalid Attribute Value"},
		{"keyset name", "resource \"cipherstash_zerokms_keyset\" \"app\" {\n name = \"bad name!\"\n description = \"invalid\"\n}", "Invalid Attribute Value"},
		{"grant identifier", fmt.Sprintf("resource \"cipherstash_zerokms_keyset_grant\" \"app\" {\n client_id = \"not-a-uuid\"\n keyset_id = %q\n}", keysetID), "Invalid Attribute Value"},
		{"missing lookup", fmt.Sprintf("data \"cipherstash_zerokms_client\" \"app\" { id = %q }", clientID), "Client not found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newServiceFixture(t)
			tc := cliTestCase(t, f)
			tc.Steps = []resource.TestStep{{Config: cliProvider + test.config, ExpectError: regexp.MustCompile(test.error)}}
			resource.UnitTest(t, tc)
			f.edit(func() {
				assert.Empty(t, f.mutations, "invalid configuration mutated inventory")
			})
		})
	}
}

// These keys are synthetic fixture values, not CipherStash credentials.
var (
	cliSeedKey      = fixtureClientKey("seed")
	cliOtherSeedKey = fixtureClientKey("other")
)

func TestCLIClientSeedFormat(t *testing.T) {
	// Independently encoded identity permutations from the published recipher
	// schema, not produced by the service fixture or the production validator.
	const identity = "pGJwMaFrcGVybXV0YXRpb26QAAECAwQFBgcICQoLDA0OD2dwMl9mcm9toWtwZXJtdXRhdGlvbpAAAQIDBAUGBwgJCgsMDQ4PZXAyX3RvoWtwZXJtdXRhdGlvbpAAAQIDBAUGBwgJCgsMDQ4PYnAzoWtwZXJtdXRhdGlvbpghAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBgYGRgaGBsYHBgdGB4YHxgg"
	for _, kind := range []string{"base64", "hex", "extended", "missing-field", "duplicate-field", "root-integer", "nested-integer", "root-null", "nested-null", "duplicate-index", "out-of-range", "short-permutation", "byte-string", "null-index", "float-index", "trailing", "truncated", "whitespace"} {
		t.Run(kind, func(t *testing.T) {
			encoded, err := base64.StdEncoding.DecodeString(identity)
			require.NoError(t, err)
			var key map[string]map[string]any
			require.NoError(t, cbor.Unmarshal(encoded, &key))
			valid := kind == "base64" || kind == "hex" || kind == "extended"
			switch kind {
			case "extended":
				key["future"] = map[string]any{"ignored": true}
				key["p1"]["future"] = true
			case "missing-field":
				delete(key, "p2_to")
			case "duplicate-index":
				key["p1"]["permutation"].([]any)[0] = uint64(1)
			case "out-of-range":
				key["p3"]["permutation"].([]any)[32] = uint64(33)
			case "short-permutation":
				key["p2_from"]["permutation"] = key["p2_from"]["permutation"].([]any)[:15]
			case "byte-string":
				key["p1"]["permutation"] = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
			case "null-index":
				key["p1"]["permutation"].([]any)[0] = nil
			case "float-index":
				key["p1"]["permutation"].([]any)[0] = float64(0)
			}
			if kind != "base64" && kind != "hex" {
				encoded, err = cbor.Marshal(key)
				require.NoError(t, err)
			}
			switch kind {
			case "duplicate-field":
				encoded[0]++ // Four-entry map becomes five, with the same valid p1 twice.
				duplicate, err := cbor.Marshal(key["p1"])
				require.NoError(t, err)
				encoded = append(append(encoded, 0x62, 'p', '1'), duplicate...)
			case "root-integer", "root-null":
				encoded[0]++ // Serde treats integer 0 as another p1 field, not an unknown field.
				field := byte(0x00)
				if kind == "root-null" {
					field = 0xf6
				}
				encoded = append(encoded, field, 0xf6)
			case "nested-integer", "nested-null":
				var raw map[string]cbor.RawMessage
				require.NoError(t, cbor.Unmarshal(encoded, &raw))
				raw["p1"][0]++ // Integer 0 aliases permutation inside this map.
				field := byte(0x00)
				if kind == "nested-null" {
					field = 0xf6
				}
				raw["p1"] = append(raw["p1"], field, 0xf6)
				encoded, err = cbor.Marshal(raw)
				require.NoError(t, err)
			case "trailing":
				encoded = append(encoded, 0)
			case "truncated":
				encoded = encoded[:len(encoded)-1]
			}
			input := base64.StdEncoding.EncodeToString(encoded)
			if kind == "hex" {
				input = strings.ToUpper(hex.EncodeToString(encoded))
			} else if kind == "whitespace" {
				input += "\n"
			}
			f := newServiceFixture(t)
			f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID}}}
			tc := cliTestCase(t, f)
			step := resource.TestStep{Config: fmt.Sprintf(cliSeedClient, fmt.Sprintf("client_key = %q\nclient_key_client_id = %q", input, clientID))}
			if valid {
				step.Check = resource.TestCheckResourceAttr("cipherstash_zerokms_client.app", "client_key", input)
			} else {
				step.ExpectError = regexp.MustCompile("Cannot seed client key")
			}
			tc.Steps = []resource.TestStep{
				{Config: cliProvider},
				{Config: fmt.Sprintf(cliSeedClient, ""), ResourceName: "cipherstash_zerokms_client.app", ImportState: true, ImportStatePersist: true, ImportStateId: clientID},
				step,
				{PreConfig: func() { f.edit(func() { require.Empty(t, f.mutations, "format check wrote to CipherStash") }) }, Config: fmt.Sprintf(cliSeedClient, "")},
			}
			resource.UnitTest(t, tc)
		})
	}
}

const cliSeedClient = cliProvider + `
resource "cipherstash_zerokms_client" "app" {
  name = "imported"
  description = "existing"
  %s
}
`

func TestCLIClientKeySeeding(t *testing.T) {
	f := newServiceFixture(t)
	f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID, tenantKeysetID}}}
	tc := cliTestCase(t, f)
	plain := fmt.Sprintf(cliSeedClient, "")
	seed := fmt.Sprintf("client_key = %q\nclient_key_client_id = %q", cliSeedKey, clientID)
	check := func(s *terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		c := s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary
		if c.ID != clientID || c.Attributes["client_key"] != cliSeedKey || len(f.mutations) != 0 || !slices.Equal(f.clients[0].KeysetIDs, []string{keysetID, tenantKeysetID}) {
			return fmt.Errorf("seeding or refresh changed identity/grants, lost the key, or wrote to CipherStash")
		}
		return nil
	}
	tc.Steps = []resource.TestStep{
		{Config: cliProvider},
		{Config: plain, ResourceName: "cipherstash_zerokms_client.app", ImportState: true, ImportStatePersist: true, ImportStateId: clientID},
		{Config: fmt.Sprintf(cliSeedClient, seed+"\nlifecycle { ignore_changes = [client_key] }"), ConfigStateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue("cipherstash_zerokms_client.app", tfjsonpath.New("client_key"), knownvalue.Null())}},
		{Config: fmt.Sprintf(cliSeedClient, seed), Check: check, ConfigStateChecks: []statecheck.StateCheck{statecheck.ExpectSensitiveValue("cipherstash_zerokms_client.app", tfjsonpath.New("client_key"))}, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("cipherstash_zerokms_client.app", plancheck.ResourceActionUpdate)}}},
		{RefreshState: true, Check: check},
		{Config: fmt.Sprintf(cliSeedClient, seed), Check: check, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
	}
	// Ignored invalid, different and unknown keys retain the old state value.
	for _, input := range []string{`"invalid"`, fmt.Sprintf("%q", cliOtherSeedKey), "terraform_data.key.output"} {
		config := fmt.Sprintf(cliSeedClient, fmt.Sprintf("client_key = %s\nclient_key_client_id = %q\nlifecycle { ignore_changes = [client_key] }", input, clientID))
		if input == "terraform_data.key.output" {
			config += fmt.Sprintf("resource \"terraform_data\" \"key\" { input = %q }", cliOtherSeedKey)
		}
		tc.Steps = append(tc.Steps, resource.TestStep{Config: config, Check: check, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("cipherstash_zerokms_client.app", plancheck.ResourceActionNoop)}}})
	}
	tc.Steps = append(tc.Steps,
		resource.TestStep{Config: plain, Check: check},
		resource.TestStep{Config: fmt.Sprintf(cliSeedClient, "client_key = null\nclient_key_client_id = null"), Check: check, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
	)
	resource.UnitTest(t, tc)
}

func TestCLIClientRetainedKeyIgnoreChanges(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		for _, ignore := range []string{"all", "[client_key]"} {
			t.Run(fmt.Sprintf("seeded=%t/ignore=%s", seeded, ignore), func(t *testing.T) {
				f := newServiceFixture(t)
				tc := cliTestCase(t, f)
				plain := fmt.Sprintf(cliSeedClient, "")
				var originalID, originalKey string
				var originalGrants []string
				var writes int
				remember := func(s *terraform.State) error {
					f.mu.Lock()
					defer f.mu.Unlock()
					c := s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary
					originalID, originalKey = c.ID, c.Attributes["client_key"]
					originalGrants = slices.Clone(f.clients[0].KeysetIDs)
					writes = len(f.mutations)
					if originalID == "" || originalKey == "" {
						return fmt.Errorf("setup did not persist a client UUID and key")
					}
					return nil
				}
				if seeded {
					f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID, tenantKeysetID}}}
					tc.Steps = []resource.TestStep{
						{Config: cliProvider},
						{Config: plain, ResourceName: "cipherstash_zerokms_client.app", ImportState: true, ImportStatePersist: true, ImportStateId: clientID},
						{Config: fmt.Sprintf(cliSeedClient, fmt.Sprintf("client_key = %q\nclient_key_client_id = %q", cliSeedKey, clientID)), Check: remember},
					}
				} else {
					tc.Steps = []resource.TestStep{{Config: plain, Check: remember}}
				}
				check := func(s *terraform.State) error {
					f.mu.Lock()
					defer f.mu.Unlock()
					c := s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary
					if c.ID != originalID || c.Attributes["client_key"] != originalKey || len(f.clients) != 1 || !slices.Equal(f.clients[0].KeysetIDs, originalGrants) || len(f.mutations) != writes {
						return fmt.Errorf("ignoring retained key changed identity/key/grants or wrote to CipherStash")
					}
					return nil
				}
				if seeded {
					tc.Steps = append(tc.Steps, resource.TestStep{Config: fmt.Sprintf(cliSeedClient, fmt.Sprintf("client_key = %q\nclient_key_client_id = %q\nlifecycle { ignore_changes = %s }", cliSeedKey, clientID, ignore)), Check: check})
				}
				config := fmt.Sprintf(cliSeedClient, fmt.Sprintf("lifecycle { ignore_changes = %s }", ignore))
				tc.Steps = append(tc.Steps,
					resource.TestStep{Config: config, Check: check},
					resource.TestStep{Config: config, Check: check, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
				)
				resource.UnitTest(t, tc)
			})
		}
	}
}

func TestCLIClientSeedValidation(t *testing.T) {
	for _, kind := range []string{"missing-uuid", "wrong-uuid", "retained-key-wrong-uuid", "invalid-key", "short-key", "raw32-key", "opaque168-key", "different-key", "unknown-key", "unknown-uuid", "create", "uuid-only-create"} {
		t.Run(kind, func(t *testing.T) {
			f := newServiceFixture(t)
			f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID}}}
			tc := cliTestCase(t, f)
			plain := fmt.Sprintf(cliSeedClient, "")
			tc.Steps = []resource.TestStep{{Config: cliProvider}, {Config: plain, ResourceName: "cipherstash_zerokms_client.app", ImportState: true, ImportStatePersist: true, ImportStateId: clientID}}
			key, id, extra := fmt.Sprintf("%q", cliSeedKey), fmt.Sprintf("%q", clientID), ""
			switch kind {
			case "missing-uuid":
				id = "null"
			case "wrong-uuid", "retained-key-wrong-uuid":
				if kind == "retained-key-wrong-uuid" {
					tc.Steps = append(tc.Steps, resource.TestStep{Config: fmt.Sprintf(cliSeedClient, fmt.Sprintf("client_key = %s\nclient_key_client_id = %s", key, id))})
				}
				id = fmt.Sprintf("%q", tenantKeysetID)
				// The declared UUID exists, but is not the imported client. Merely
				// checking its existence would accept this stale UUID/key pair.
				f.clients = append(f.clients, control.ZeroKMSClient{ID: tenantKeysetID, Name: "other", Description: "unmanaged", KeysetIDs: []string{keysetID}})
				tc.CheckDestroy = func(*terraform.State) error {
					f.mu.Lock()
					defer f.mu.Unlock()
					if len(f.clients) != 1 || f.clients[0].ID != tenantKeysetID {
						return fmt.Errorf("unmanaged client changed")
					}
					return nil
				}
			case "invalid-key":
				key = `"not-base64"`
			case "short-key":
				key = `"AQIDBA=="`
			case "raw32-key":
				key = fmt.Sprintf("%q", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))))
			case "opaque168-key":
				key = fmt.Sprintf("%q", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 168))))
			case "different-key":
				tc.Steps = append(tc.Steps, resource.TestStep{Config: fmt.Sprintf(cliSeedClient, fmt.Sprintf("client_key = %s\nclient_key_client_id = %s", key, id))})
				key = fmt.Sprintf("%q", cliOtherSeedKey)
			case "unknown-key":
				key = "terraform_data.value.output"
				extra = fmt.Sprintf("resource \"terraform_data\" \"value\" { input = %q }", cliSeedKey)
			case "unknown-uuid":
				id = "terraform_data.value.output"
				extra = fmt.Sprintf("resource \"terraform_data\" \"value\" { input = %q }", clientID)
			case "create", "uuid-only-create":
				f.clients, tc.Steps = nil, nil
				if kind == "uuid-only-create" {
					key = "null"
				}
			}
			tc.Steps = append(tc.Steps,
				resource.TestStep{Config: fmt.Sprintf(cliSeedClient, fmt.Sprintf("client_key = %s\nclient_key_client_id = %s", key, id)) + extra, ExpectError: regexp.MustCompile("Cannot seed client key")},
				resource.TestStep{PreConfig: func() { f.edit(func() { require.Empty(t, f.mutations, "rejected seed mutated CipherStash") }) }, Config: cliProvider},
			)
			resource.UnitTest(t, tc)
		})
	}
}

func TestCLIClientSeedReplacement(t *testing.T) {
	for _, mode := range []string{"metadata", "taint", "replace", "missing"} {
		for _, createFirst := range []bool{false, true} {
			for _, keepSeed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/create-first=%t/keep-seed=%t", mode, createFirst, keepSeed), func(t *testing.T) {
					f := newServiceFixture(t)
					f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID}}}
					tc := cliTestCase(t, f)
					lifecycle := fmt.Sprintf("lifecycle { create_before_destroy = %t }", createFirst)
					plain := fmt.Sprintf(cliSeedClient, lifecycle)
					seed := fmt.Sprintf(cliSeedClient, fmt.Sprintf("client_key = %q\nclient_key_client_id = %q\n%s", cliSeedKey, clientID, lifecycle))
					tc.Steps = []resource.TestStep{
						{Config: cliProvider},
						{Config: plain, ResourceName: "cipherstash_zerokms_client.app", ImportState: true, ImportStatePersist: true, ImportStateId: clientID},
						{Config: seed},
					}
					config := seed
					if !keepSeed {
						config = plain
						tc.Steps = append(tc.Steps, resource.TestStep{Config: plain})
					}
					step := resource.TestStep{Config: config}
					switch mode {
					case "metadata":
						step.Config = strings.Replace(config, `name = "imported"`, `name = "replacement"`, 1)
					case "taint":
						step.Taint = []string{"cipherstash_zerokms_client.app"}
					case "replace":
						step.PreConfig = func() { t.Setenv("TF_CLI_ARGS_plan", "-replace=cipherstash_zerokms_client.app") }
						step.ExpectNonEmptyPlan = true
					case "missing":
						step.PreConfig = func() { f.edit(func() { f.clients = nil }) }
					}
					if keepSeed {
						step.ExpectError = regexp.MustCompile("Cannot seed client key")
					} else {
						step.Check = func(s *terraform.State) error {
							f.mu.Lock()
							defer f.mu.Unlock()
							c := s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary
							if len(f.clients) != 1 || c.ID == clientID || c.Attributes["client_key"] == cliSeedKey || c.Attributes["client_key"] != f.secrets[c.ID] {
								return fmt.Errorf("replacement reused the seeded UUID/key or failed to retain its new key")
							}
							return nil
						}
					}
					tc.Steps = append(tc.Steps, step, resource.TestStep{PreConfig: func() {
						t.Setenv("TF_CLI_ARGS_plan", "")
						if keepSeed {
							f.edit(func() { require.Empty(t, f.mutations, "unsafe replacement wrote before rejection") })
						}
					}, Config: cliProvider})
					resource.UnitTest(t, tc)
				})
			}
		}
	}
}

type seedClientDriftAfterPlan struct {
	fixture     *serviceFixture
	readFailure bool
}

func (check seedClientDriftAfterPlan) CheckPlan(_ context.Context, _ plancheck.CheckPlanRequest, _ *plancheck.CheckPlanResponse) {
	check.fixture.edit(func() {
		if check.readFailure {
			check.fixture.faults = []serviceFault{{path: "/list-clients", status: 500}}
		} else {
			check.fixture.clients = nil
		}
	})
}

func TestCLIClientSeedSavedPlan(t *testing.T) {
	for _, readFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("read-failure=%t", readFailure), func(t *testing.T) {
			f := newServiceFixture(t)
			f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID}}}
			tc := cliTestCase(t, f)
			expected := "The planned client no longer exists"
			if readFailure {
				expected = "Cannot read client"
			}
			tc.Steps = []resource.TestStep{
				{Config: cliProvider},
				{Config: fmt.Sprintf(cliSeedClient, ""), ResourceName: "cipherstash_zerokms_client.app", ImportState: true, ImportStatePersist: true, ImportStateId: clientID},
				{Config: fmt.Sprintf(cliSeedClient, fmt.Sprintf("client_key = %q\nclient_key_client_id = %q", cliSeedKey, clientID)), ExpectError: regexp.MustCompile(expected), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{seedClientDriftAfterPlan{f, readFailure}}}},
				{PreConfig: func() {
					f.edit(func() { require.Empty(t, f.mutations, "failed saved adoption plan wrote to CipherStash") })
				}, Config: cliProvider},
			}
			resource.UnitTest(t, tc)
		})
	}
}

// Generate short command sequences against Terraform, not synthetic ModifyPlan
// inputs: ignore_changes and replacement replanning belong to Terraform itself.
func TestCLIClientLifecycleModel(t *testing.T) {
	f := newServiceFixture(t)
	cliTestCase(t, f) // Reuse pinned CLI, isolated CLI config and native auth transport.
	p := New()
	defer p.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	configs := make(chan *plugin.ReattachConfig, 1)
	closed := make(chan struct{})
	served := make(chan error, 1)
	go func() {
		served <- tf6server.Serve("registry.terraform.io/hashicorp/cipherstash", func() tfprotov6.ProviderServer {
			return Protocol6(p)
		}, tf6server.WithDebug(ctx, configs, closed))
	}()
	var config *plugin.ReattachConfig
	select {
	case config = <-configs:
	case err := <-served:
		t.Fatalf("provider server exited before reattach: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("provider server did not start")
	}
	defer func() {
		cancel()
		<-closed
		require.NoError(t, <-served)
	}()
	reattach := tfexec.Reattach(tfexec.ReattachInfo{
		"registry.terraform.io/hashicorp/cipherstash": {
			Protocol: string(config.Protocol), ProtocolVersion: config.ProtocolVersion,
			Pid: config.Pid, Test: config.Test,
			Addr: tfexec.ReattachConfigAddr{Network: config.Addr.Network(), String: config.Addr.String()},
		},
	})
	// Fixed traces retain the known regressions even when the random budget is small.
	for _, createFirst := range []bool{false, true} {
		for _, seeded := range []bool{false, true} {
			t.Run(fmt.Sprintf("regression/create-first=%t/seeded=%t", createFirst, seeded), func(t *testing.T) {
				actions := []string{"ignore-key", "key-only", "metadata", "remove-seed", "metadata"}
				if seeded {
					actions = []string{"seed", "ignore-key", "metadata", "remove-seed", "metadata"}
				}
				testCLIClientTrace(t, f, reattach, seeded, createFirst, actions)
			})
		}
	}
	t.Run("generated", func(t *testing.T) {
		rapid.Check(t, func(r *rapid.T) {
			imported := rapid.Bool().Draw(r, "imported")
			createFirst := rapid.Bool().Draw(r, "create-first")
			actions := rapid.SliceOfN(rapid.SampledFrom([]string{
				"ignore-key", "ignore-all", "ignore-none", "seed", "remove-seed",
				"wrong-uuid", "different-key", "metadata", "replace", "refresh",
			}), 1, 6).Draw(r, "actions")
			testCLIClientTrace(r, f, reattach, imported, createFirst, actions)
		})
	})
}

func testCLIClientTrace(t rapid.TB, f *serviceFixture, reattach *tfexec.ReattachOption, imported, createFirst bool, actions []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "cipherstash-lifecycle-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	binary, err := exec.LookPath("terraform")
	require.NoError(t, err)
	tf, err := tfexec.NewTerraform(dir, binary)
	require.NoError(t, err)
	f.edit(func() {
		f.clients, f.mutations, f.requests = nil, nil, nil
		f.secrets = map[string]string{}
		if imported {
			f.clients = []control.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID, tenantKeysetID}}}
		}
	})
	// The model separates operator configuration from persisted identity/secret.
	// It describes allowed operations, without emulating Terraform's plan values.
	type configuration struct{ name, key, assertion, ignore string }
	cfg := configuration{name: "imported", ignore: "[]"}
	writeConfig := func() {
		seed := ""
		if cfg.key != "" {
			seed = fmt.Sprintf("client_key = %q\n", cfg.key)
		}
		if cfg.assertion != "" {
			seed += fmt.Sprintf("client_key_client_id = %q\n", cfg.assertion)
		}
		hcl := cliProvider + fmt.Sprintf(`
resource "cipherstash_zerokms_client" "app" {
  name = %q
  description = "existing"
  %s
  lifecycle {
    ignore_changes = %s
    create_before_destroy = %t
  }
}
`, cfg.name, seed, cfg.ignore, createFirst)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(hcl), 0o600))
	}
	writeConfig()
	require.NoError(t, tf.Init(ctx, reattach))
	if imported {
		require.NoError(t, tf.Import(ctx, "cipherstash_zerokms_client.app", clientID, reattach))
	} else {
		require.NoError(t, tf.Apply(ctx, reattach))
	}
	// Clean even a failing/shrinking trace through Terraform, never by editing state.
	defer func() {
		cfg.key, cfg.assertion = "", ""
		writeConfig()
		require.NoError(t, tf.Destroy(ctx, reattach))
		f.edit(func() { require.Empty(t, f.clients, "destroy left a test client") })
	}()
	readState := func() map[string]interface{} {
		s, err := tf.Show(ctx, reattach)
		require.NoError(t, err)
		require.NotNil(t, s.Values)
		require.Len(t, s.Values.RootModule.Resources, 1)
		return s.Values.RootModule.Resources[0].AttributeValues
	}
	state := readState()
	id := state["id"].(string)
	key, binding := "", ""
	grants := []string{keysetID, tenantKeysetID}
	if !imported {
		f.edit(func() { key = f.secrets[id] })
		grants = []string{keysetID}
	} else {
		require.Equal(t, clientID, id)
	}
	name := cfg.name
	check := func() {
		s := readState()
		actualKey, _ := s["client_key"].(string)
		actualBinding, _ := s["client_key_client_id"].(string)
		if s["id"] != id || actualKey != key || actualBinding != binding || s["name"] != name {
			t.Fatal("Terraform identity, key, UUID assertion or metadata differs from lifecycle model")
		}
		f.edit(func() {
			if len(f.clients) != 1 || f.clients[0].ID != id || f.clients[0].Name != name || !slices.Equal(f.clients[0].KeysetIDs, grants) {
				t.Fatal("service inventory differs from lifecycle model")
			}
		})
	}
	check()
	for i, action := range actions {
		t.Logf("action %d: %s", i, action)
		previous := cfg
		switch action {
		case "ignore-key":
			cfg.ignore = "[client_key]"
		case "ignore-all":
			cfg.ignore = "all"
		case "ignore-none":
			cfg.ignore = "[]"
		case "seed", "key-only", "wrong-uuid", "different-key":
			cfg.key, cfg.assertion = key, id
			if cfg.key == "" {
				cfg.key = cliSeedKey
			}
			if action == "key-only" {
				cfg.assertion = ""
			}
			if action == "wrong-uuid" {
				cfg.assertion = tenantKeysetID
			}
			if action == "different-key" {
				cfg.key = cliOtherSeedKey
			}
		case "remove-seed":
			cfg.key, cfg.assertion = "", ""
		case "metadata":
			cfg.name += "-edited"
		}
		writeConfig()
		var writes int
		f.edit(func() { writes = len(f.mutations) })
		if action == "refresh" {
			require.NoError(t, tf.Apply(ctx, reattach, tfexec.RefreshOnly(true)))
		} else {
			nextName, nextKey, nextBinding := cfg.name, cfg.key, cfg.assertion
			if cfg.ignore == "all" {
				nextName, nextBinding = name, binding
			}
			if cfg.ignore != "[]" || nextKey == "" {
				nextKey = key
			}
			replacement := action == "replace" || nextName != name
			// Existing keys are immutable. Only missing keys can be adopted,
			// with a matching assertion; replacement needs seed-free config.
			reject := (nextBinding != "" && nextBinding != id) ||
				(nextKey != key && (key != "" || nextBinding != id)) ||
				(replacement && (cfg.key != "" || cfg.assertion != ""))
			opts := []tfexec.PlanOption{reattach, tfexec.Out("action.tfplan")}
			if action == "replace" {
				opts = append(opts, tfexec.Replace("cipherstash_zerokms_client.app"))
			}
			_, err := tf.Plan(ctx, opts...)
			if reject {
				if err == nil || !strings.Contains(err.Error(), "Cannot seed client key") {
					t.Fatal("unsafe operation did not fail during planning with a seeding diagnostic")
				}
				cfg = previous
			} else {
				require.NoError(t, err, "permitted lifecycle action must plan successfully")
				require.NoError(t, tf.Apply(ctx, reattach, tfexec.DirOrPlan("action.tfplan")))
				if replacement {
					oldID, oldKey := id, key
					f.edit(func() {
						require.Len(t, f.clients, 1)
						id = f.clients[0].ID
						key = f.secrets[id]
						want := []string{"/delete-client", "/create-client"}
						if createFirst {
							slices.Reverse(want)
						}
						require.Equal(t, want, f.mutations[writes:])
						writes = len(f.mutations)
					})
					if id == oldID || key == "" || key == oldKey {
						t.Fatal("replacement reused the old identity/key")
					}
					name, binding, grants = cfg.name, "", []string{keysetID}
				} else {
					name, key, binding = nextName, nextKey, nextBinding
				}
			}
		}
		f.edit(func() { require.Len(t, f.mutations, writes, "retention, adoption or rejection wrote to CipherStash") })
		check()
	}
}
