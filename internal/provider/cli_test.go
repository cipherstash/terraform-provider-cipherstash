package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	control "github.com/cipherstash/terraform-provider-cipherstash/internal/stack/manage"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cliProvider = `
provider "cipherstash" {
  crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"
  access_key = "CSAKtestKeyId.testKeySecret"
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
resource "cipherstash_actor" "api" {
  name = %q
  kind = "agent"
  role = "control"
  token_expiry = 1234
}
resource "cipherstash_client" "api" {
  name = %q
  description = "API encryption"
}
data "cipherstash_client" "api" { id = cipherstash_client.api.id }
`, name, name)
	}
	var originalActor, originalClient, actorSecret, clientSecret string
	check := func(replaced bool) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			a := s.RootModule().Resources["cipherstash_actor.api"].Primary
			c := s.RootModule().Resources["cipherstash_client.api"].Primary
			d := s.RootModule().Resources["data.cipherstash_client.api"].Primary
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
			statecheck.ExpectSensitiveValue("cipherstash_actor.api", tfjsonpath.New("access_key")),
			statecheck.ExpectSensitiveValue("cipherstash_client.api", tfjsonpath.New("client_key")),
		}},
		{Config: configuration("api"), Check: check(false), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{Config: configuration("api-v2"), Check: check(true), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction("cipherstash_actor.api", plancheck.ResourceActionDestroyBeforeCreate),
			plancheck.ExpectResourceAction("cipherstash_client.api", plancheck.ResourceActionDestroyBeforeCreate),
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
resource "cipherstash_keyset" "app" {
  name = "application"
  description = %q
  enabled = %t
}
`, description, enabled)
			}
			var id string
			check := func(enabled bool, description string) resource.TestCheckFunc {
				return func(s *terraform.State) error {
					f.mu.Lock()
					defer f.mu.Unlock()

					current := s.RootModule().Resources["cipherstash_keyset.app"].Primary.ID
					if id != "" && id != current {
						return fmt.Errorf("keyset update replaced identity")
					}

					id = current
					i := slices.IndexFunc(f.keysets, func(k control.Keyset) bool { return k.ID == id })
					if i < 0 || f.keysets[i].IsDisabled == enabled || f.keysets[i].Description != description {
						return fmt.Errorf("keyset inventory does not match configuration")
					}

					return nil
				}
			}
			tc.Steps = []resource.TestStep{
				{Config: configuration("initial", initiallyEnabled), Check: check(initiallyEnabled, "initial")},
				{Config: configuration("updated", !initiallyEnabled), Check: check(!initiallyEnabled, "updated"), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("cipherstash_keyset.app", plancheck.ResourceActionUpdate)}}},
				{Config: configuration("updated", initiallyEnabled), Check: check(initiallyEnabled, "updated")},
			}
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
resource "cipherstash_client" "api" {
  name = "api"
  description = "application client"
}
resource "cipherstash_keyset" "app" {
  name = "application"
  description = "application keyset"
}
`
	grant := func(expression string) string {
		return base + fmt.Sprintf(`
resource "cipherstash_keyset_grant" "app" {
  client_id = cipherstash_client.api.id
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

			if g := s.RootModule().Resources["cipherstash_keyset_grant.app"]; g != nil {
				if !slices.Contains(f.clients[0].KeysetIDs, g.Primary.Attributes["keyset_id"]) || g.Primary.ID != f.clients[0].ID+"/"+g.Primary.Attributes["keyset_id"] {
					return fmt.Errorf("grant state does not identify the owned pair")
				}
			}

			return nil
		}
	}
	tc.Steps = []resource.TestStep{
		{Config: grant("cipherstash_keyset.app.id"), Check: check(2)},
		{Config: grant(fmt.Sprintf("%q", tenantKeysetID)), Check: check(2), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction("cipherstash_keyset_grant.app", plancheck.ResourceActionDestroyBeforeCreate),
			plancheck.ExpectResourceAction("cipherstash_client.api", plancheck.ResourceActionNoop),
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
		{Config: grant("cipherstash_client.api.keyset_id"), ExpectError: regexp.MustCompile("Grant already exists")},
		{Config: base, Check: check(2), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{
			Config: grant(fmt.Sprintf("%q", keysetID)), ResourceName: "cipherstash_keyset_grant.app", ImportState: true, ImportStatePersist: true,
			ImportStateIdFunc: func(s *terraform.State) (string, error) {
				return s.RootModule().Resources["cipherstash_client.api"].Primary.ID + "/" + keysetID, nil
			},
		},
		{Config: grant(fmt.Sprintf("%q", keysetID)), Check: check(2), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{Config: base, Check: func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			client := s.RootModule().Resources["cipherstash_client.api"].Primary
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
				id, address = "app-imported", "cipherstash_actor.app"
				f.actors = []control.Actor{{ID: id, Name: "imported", Kind: "app", CreatedAt: fixtureTimestamp}}
				f.keys = []control.AccessKeyMetadata{{ID: "key-" + id, Name: "imported", Role: "member", CreatedAt: fixtureTimestamp}}
				config = `resource "cipherstash_actor" "app" { name = "imported" }`
				checks = []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("access_key"), knownvalue.Null()),
					statecheck.ExpectKnownValue(address, tfjsonpath.New("token_expiry"), knownvalue.Null()),
				}
			case "client", "client-zero-grants", "client-many-grants", "client-legacy-pair", "client-legacy-absent-grant":
				id, address = clientID, "cipherstash_client.app"
				f.clients = []control.EncryptionClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID}}}
				config = "resource \"cipherstash_client\" \"app\" {\n name = \"imported\"\n description = \"existing\"\n}"
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
				id, address = tenantKeysetID, "cipherstash_keyset.app"
				f.keysets[1].IsDisabled = true
				config = "resource \"cipherstash_keyset\" \"app\" {\n name = \"external\"\n description = \"Worker owned\"\n enabled = false\n}"
				checks = []statecheck.StateCheck{statecheck.ExpectKnownValue(address, tfjsonpath.New("enabled"), knownvalue.Bool(false))}
			case "keyset_grant":
				id, address = clientID+"/"+tenantKeysetID, "cipherstash_keyset_grant.app"
				f.clients = []control.EncryptionClient{{ID: clientID, Name: "external", KeysetIDs: []string{keysetID, tenantKeysetID}}}
				config = fmt.Sprintf("resource \"cipherstash_keyset_grant\" \"app\" {\n client_id = %q\n keyset_id = %q\n}", clientID, tenantKeysetID)
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
		if change.Address != "cipherstash_actor.app" {
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

		return cliProvider + fmt.Sprintf("resource \"cipherstash_actor\" \"app\" {\n name = %q\n %s\n}", name, lifecycle)
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

			state := s.RootModule().Resources["cipherstash_actor.app"].Primary
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
resource "cipherstash_actor" "app" { name = "app" }
resource "cipherstash_client" "app" {
  name = "app"
  description = "application"
}
resource "cipherstash_keyset" "app" {
  name = "application"
  description = "owned metadata"
}
resource "cipherstash_keyset_grant" "app" {
  client_id = cipherstash_client.app.id
  keyset_id = cipherstash_keyset.app.id
}
`
		var oldActor, oldClient, oldKeyset string
		tc.Steps = []resource.TestStep{
			{Config: config, Check: func(s *terraform.State) error {
				oldActor = s.RootModule().Resources["cipherstash_actor.app"].Primary.ID
				oldClient = s.RootModule().Resources["cipherstash_client.app"].Primary.ID
				oldKeyset = s.RootModule().Resources["cipherstash_keyset.app"].Primary.ID

				return nil
			}},
			{PreConfig: func() {
				f.edit(func() {
					f.actors, f.keys, f.clients = nil, nil, nil
					f.keysets[2].Description = "external edit"
					f.keysets[2].IsDisabled = true
				})
			}, Config: config, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("cipherstash_actor.app", plancheck.ResourceActionCreate),
				plancheck.ExpectResourceAction("cipherstash_client.app", plancheck.ResourceActionCreate),
				plancheck.ExpectResourceAction("cipherstash_keyset.app", plancheck.ResourceActionUpdate),
				plancheck.ExpectResourceAction("cipherstash_keyset_grant.app", plancheck.ResourceActionCreate),
			}}, Check: func(s *terraform.State) error {
				f.mu.Lock()
				defer f.mu.Unlock()

				if s.RootModule().Resources["cipherstash_actor.app"].Primary.ID == oldActor || s.RootModule().Resources["cipherstash_client.app"].Primary.ID == oldClient || s.RootModule().Resources["cipherstash_keyset.app"].Primary.ID != oldKeyset {
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
		config := cliProvider + "resource \"cipherstash_client\" \"app\" {\n name = \"app\"\n description = \"application\"\n}"
		var id, secret string
		check := func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			client := s.RootModule().Resources["cipherstash_client.app"].Primary
			if client.ID != id || client.Attributes["client_key"] != secret || client.Attributes["keyset_id"] != keysetID || len(f.mutations) != 1 {
				return fmt.Errorf("refresh changed client identity, creation secret, historical keyset or grants")
			}

			return nil
		}
		tc.Steps = []resource.TestStep{
			{Config: config, Check: func(s *terraform.State) error {
				client := s.RootModule().Resources["cipherstash_client.app"].Primary
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

func TestCLIValidation(t *testing.T) {
	for _, expiry := range []int64{1, 86400} {
		t.Run(fmt.Sprintf("valid token lifetime %d", expiry), func(t *testing.T) {
			f := newServiceFixture(t)
			tc := cliTestCase(t, f)
			tc.Steps = []resource.TestStep{{
				Config:            cliProvider + fmt.Sprintf("resource \"cipherstash_actor\" \"app\" {\n name = \"app\"\n token_expiry = %d\n}", expiry),
				ConfigStateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue("cipherstash_actor.app", tfjsonpath.New("token_expiry"), knownvalue.Int64Exact(expiry))},
			}}
			resource.UnitTest(t, tc)
		})
	}

	for _, test := range []struct{ name, config, error string }{
		{"actor kind", "resource \"cipherstash_actor\" \"app\" {\n name = \"app\"\n kind = \"human\"\n}", "Invalid Attribute Value Match"},
		{"actor role", "resource \"cipherstash_actor\" \"app\" {\n name = \"app\"\n role = \"owner\"\n}", "Invalid Attribute Value Match"},
		{"token below minimum", "resource \"cipherstash_actor\" \"app\" {\n name = \"app\"\n token_expiry = 0\n}", "Invalid Attribute Value"},
		{"token above maximum", "resource \"cipherstash_actor\" \"app\" {\n name = \"app\"\n token_expiry = 86401\n}", "Invalid Attribute Value"},
		{"keyset name", "resource \"cipherstash_keyset\" \"app\" {\n name = \"bad name!\"\n description = \"invalid\"\n}", "Invalid Attribute Value"},
		{"grant identifier", fmt.Sprintf("resource \"cipherstash_keyset_grant\" \"app\" {\n client_id = \"not-a-uuid\"\n keyset_id = %q\n}", keysetID), "Invalid Attribute Value"},
		{"missing lookup", fmt.Sprintf("data \"cipherstash_client\" \"app\" { id = %q }", clientID), "Client not found"},
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
