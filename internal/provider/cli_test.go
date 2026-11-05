package provider

import (
	"context"
	"crypto/rand"
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

	"github.com/cipherstash/terraform-provider-cipherstash/internal/eql"
	"github.com/cipherstash/terraform-provider-cipherstash/pkg/stack/manage"
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
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

const cliProvider = `
provider "cipherstash" {
  auth = {
    workspace_crn     = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"
    client_access_key = "CSAKtestKeyId.testKeySecret"
  }
}
`

func cliTestCase(t *testing.T, f *serviceFixture) resource.TestCase {
	t.Helper()
	// Never let plugin-testing download a different Terraform or use a user's
	// CLI configuration. The provider runs in-process; only Terraform is a child.
	binary, err := exec.LookPath("terraform")
	require.NoError(t, err, "Terraform 1.14.6 is required; run through mise")
	t.Setenv("CHECKPOINT_DISABLE", "1")
	t.Setenv("CS_CTS_HOST", "")
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
					i := slices.IndexFunc(f.keysets, func(k manage.ZeroKMSKeyset) bool { return k.ID == id })
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

// The workspace default keyset belongs to CipherStash: clients get it without
// configuration, and no plan may import, change, disable or destroy it.
func TestCLIDefaultKeysetIsServiceOwned(t *testing.T) {
	f := newServiceFixture(t)
	tc := cliTestCase(t, f)
	client := cliProvider + `
resource "cipherstash_zerokms_client" "api" {
  name = "api"
  description = "application client"
}
`
	keyset := func(name string) string {
		return client + fmt.Sprintf("resource \"cipherstash_zerokms_keyset\" \"app\" {\n name = %q\n description = \"Worker owned\"\n}\n", name)
	}
	noKeysetWrites := func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()

		for _, path := range f.mutations {
			if strings.Contains(path, "keyset") {
				return fmt.Errorf("unexpected keyset write %s", path)
			}
		}

		if i := slices.IndexFunc(f.keysets, func(k manage.ZeroKMSKeyset) bool { return k.IsDefault }); i < 0 || f.keysets[i].IsDisabled {
			return fmt.Errorf("the default keyset is missing or disabled")
		}

		return nil
	}
	tc.CheckDestroy = noKeysetWrites
	tc.Steps = []resource.TestStep{
		{Config: client, Check: resource.ComposeTestCheckFunc(noKeysetWrites, func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			if len(f.clients) != 1 || !slices.Equal(f.clients[0].KeysetIDs, []string{keysetID}) {
				return fmt.Errorf("a new client did not receive exactly the default keyset")
			}

			return nil
		})},
		{Config: keyset("default"), ResourceName: "cipherstash_zerokms_keyset.app", ImportState: true, ImportStateId: keysetID, ExpectError: regexp.MustCompile("Cannot import the workspace default keyset")},
		// State from before the provider refused the default: import another
		// keyset, then let the service report it as the default.
		{Config: keyset("external"), ResourceName: "cipherstash_zerokms_keyset.app", ImportState: true, ImportStatePersist: true, ImportStateId: tenantKeysetID},
		{PreConfig: func() { f.edit(func() { f.keysets[0].IsDefault, f.keysets[1].IsDefault = false, true }) }, RefreshState: true, ExpectError: regexp.MustCompile("Cannot manage the workspace default keyset")},
		{Config: keyset("renamed"), ExpectError: regexp.MustCompile("Cannot manage the workspace default keyset")},
		{Config: client, ExpectError: regexp.MustCompile("Cannot manage the workspace default keyset")},
		{Config: client + "removed {\n from = cipherstash_zerokms_keyset.app\n lifecycle {\n destroy = false\n }\n}\n", Check: noKeysetWrites},
	}
	resource.UnitTest(t, tc)
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
		{Config: grant(fmt.Sprintf("%q", keysetID)), ExpectError: regexp.MustCompile("Grant already exists")},
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
			if len(f.clients) != 1 || client.ID != f.clients[0].ID || client.Attributes["client_key"] != f.secrets[client.ID] || !slices.Equal(f.clients[0].KeysetIDs, []string{f.keysets[2].ID}) {
				return fmt.Errorf("revoking the imported default grant changed the client or an unrelated grant")
			}

			return nil
		}},
		{Config: base, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
	}
	resource.UnitTest(t, tc)
}

func TestCLIImports(t *testing.T) {
	for _, kind := range []string{"actor", "client", "client-zero-grants", "client-many-grants", "keyset", "keyset_grant"} {
		t.Run(kind, func(t *testing.T) {
			f := newServiceFixture(t)
			tc := cliTestCase(t, f)
			var address, id, config string
			var checks []statecheck.StateCheck
			var rejected []resource.TestStep
			switch kind {
			case "actor":
				id, address = "app-imported", "cipherstash_cts_actor.app"
				f.actors = []manage.CTSActor{{ID: id, Name: "imported", Kind: "app", CreatedAt: fixtureTimestamp}}
				f.keys = []manage.CTSAccessKeyMetadata{{ID: "key-" + id, Name: "imported", Role: "member", CreatedAt: fixtureTimestamp}}
				config = `resource "cipherstash_cts_actor" "app" { name = "imported" }`
				checks = []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("access_key"), knownvalue.Null()),
					statecheck.ExpectKnownValue(address, tfjsonpath.New("token_expiry"), knownvalue.Null()),
				}
			case "client", "client-zero-grants", "client-many-grants":
				id, address = clientID, "cipherstash_zerokms_client.app"
				f.clients = []manage.ZeroKMSClient{{ID: clientID, Name: "imported", Description: "existing", KeysetIDs: []string{keysetID}}}
				config = "resource \"cipherstash_zerokms_client\" \"app\" {\n name = \"imported\"\n description = \"existing\"\n}"
				switch kind {
				case "client-zero-grants":
					f.clients[0].KeysetIDs = []string{}
				case "client-many-grants":
					f.clients[0].KeysetIDs = append(f.clients[0].KeysetIDs, tenantKeysetID)
				}

				rejected = []resource.TestStep{{
					PreConfig: func() { f.edit(func() { f.faults = []serviceFault{{path: "/list-clients", status: 500}} }) },
					Config:    cliProvider + config, ResourceName: address, ImportState: true, ImportStatePersist: true, ImportStateId: id,
					ExpectError: regexp.MustCompile("Cannot import client"),
				}}

				checks = []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("client_key"), knownvalue.Null()),
				}
			case "keyset":
				id, address = tenantKeysetID, "cipherstash_zerokms_keyset.app"
				f.keysets[1].IsDisabled = true
				config = "resource \"cipherstash_zerokms_keyset\" \"app\" {\n name = \"external\"\n description = \"Worker owned\"\n enabled = false\n}"
				checks = []statecheck.StateCheck{statecheck.ExpectKnownValue(address, tfjsonpath.New("enabled"), knownvalue.Bool(false))}
			case "keyset_grant":
				id, address = clientID+"/"+tenantKeysetID, "cipherstash_zerokms_keyset_grant.app"
				f.clients = []manage.ZeroKMSClient{{ID: clientID, Name: "external", KeysetIDs: []string{keysetID, tenantKeysetID}}}
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
	t.Run("external grants", func(t *testing.T) {
		f := newServiceFixture(t)
		tc := cliTestCase(t, f)
		config := cliProvider + "resource \"cipherstash_zerokms_client\" \"app\" {\n name = \"app\"\n description = \"application\"\n}"
		var id, secret string
		check := func(s *terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			client := s.RootModule().Resources["cipherstash_zerokms_client.app"].Primary
			if client.ID != id || client.Attributes["client_key"] != secret || len(f.mutations) != 1 {
				return fmt.Errorf("refresh changed client identity, creation secret or grants")
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
		{"empty auth uses environment", `provider "cipherstash" { auth = {} }`, ""},
		{"null uses environment", "provider \"cipherstash\" {\n auth = {\n workspace_crn = null\n client_access_key = null\n }\n}", ""},
		{"explicit overrides environment", cliProvider, ""},
		{"no auth ignores environment", `provider "cipherstash" {}`, "Provider auth settings required"},
		{"database without auth ignores environment", `provider "cipherstash" { database = { host = "localhost" } }`, "Provider auth settings required"},
		{"empty crn", `provider "cipherstash" { auth = { workspace_crn = "" } }`, "Workspace CRN required"},
		{"empty key", `provider "cipherstash" { auth = { client_access_key = "" } }`, "Client access key required"},
		{"malformed crn", `provider "cipherstash" { auth = { workspace_crn = "invalid" } }`, "Invalid workspace CRN"},
		{"malformed key", `provider "cipherstash" { auth = { client_access_key = "invalid" } }`, "Invalid access key"},
		{"old top-level crn argument", `provider "cipherstash" { workspace_crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY" }`, "Unsupported argument"},
		{"old top-level key argument", `provider "cipherstash" { client_access_key = "CSAKtestKeyId.testKeySecret" }`, "Unsupported argument"},
		{"old crn argument", `provider "cipherstash" { crn = "invalid" }`, "Unsupported argument"},
		{"old control key argument", `provider "cipherstash" { control_access_key = "CSAKlegacy.secret" }`, "Unsupported argument"},
		{"old access key argument", `provider "cipherstash" { access_key = "CSAKlegacy.secret" }`, "Unsupported argument"},
		{"legacy control environment", `provider "cipherstash" { auth = {} }`, "Client access key required"},
		{"legacy cipherstash environment", `provider "cipherstash" { auth = {} }`, "Client access key required"},
		{"malformed environment crn", `provider "cipherstash" { auth = {} }`, "Invalid workspace CRN"},
		{"malformed environment key", `provider "cipherstash" { auth = {} }`, "Invalid access key"},
		{"control credential", `provider "cipherstash" { auth = {} }`, "Cannot authenticate with CipherStash"},
		{"member credential", `provider "cipherstash" { auth = {} }`, "Cannot authenticate with CipherStash"},
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
			f.clients = []manage.ZeroKMSClient{{ID: clientID, Name: "existing", KeysetIDs: []string{}}}
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

// reattachProvider serves one in-process provider for tfexec commands until
// the test ends, so model tests skip plugin-testing's per-step setup.
func reattachProvider(t *testing.T) *tfexec.ReattachOption {
	t.Helper()
	p := New()

	ctx, cancel := context.WithCancel(t.Context())
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
		cancel()
		t.Fatalf("provider server exited before reattach: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("provider server did not start")
	}

	t.Cleanup(func() {
		cancel()
		<-closed
		require.NoError(t, <-served)
		p.Close()
	})

	return tfexec.Reattach(tfexec.ReattachInfo{
		"registry.terraform.io/hashicorp/cipherstash": {
			Protocol: string(config.Protocol), ProtocolVersion: config.ProtocolVersion,
			Pid: config.Pid, Test: config.Test,
			Addr: tfexec.ReattachConfigAddr{Network: config.Addr.Network(), String: config.Addr.String()},
		},
	})
}

// testPostgres creates a database on the server in CS_TEST_POSTGRES_URL and
// returns a superuser connection to it plus provider settings that reach it.
func testPostgres(t *testing.T) (*pgx.Conn, string) {
	t.Helper()

	admin := postgresAdmin(t)
	db, drop := createDatabase(t, admin)
	// t.Context is cancelled before cleanups run, so drop uses its own.
	t.Cleanup(drop)

	return db, postgresProvider(admin)
}

// postgresAdmin is the superuser connection in CS_TEST_POSTGRES_URL. Tests
// without it skip.
func postgresAdmin(t *testing.T) *pgx.ConnConfig {
	t.Helper()

	url := os.Getenv("CS_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("CS_TEST_POSTGRES_URL is not set")
	}

	admin, err := pgx.ParseConfig(url)
	require.NoError(t, err)

	return admin
}

// createDatabase creates a uniquely named database and returns a superuser
// connection to it and a function that closes the connection and drops the
// database.
func createDatabase(t rapid.TB, admin *pgx.ConnConfig) (*pgx.Conn, func()) {
	t.Helper()

	ctx := context.Background()
	name := "tf_eql_" + strings.ToLower(rand.Text()[:12])
	run := func(sql string) {
		conn, err := pgx.ConnectConfig(ctx, admin)
		require.NoError(t, err)
		defer func() { _ = conn.Close(ctx) }()

		_, err = conn.Exec(ctx, sql)
		require.NoError(t, err)
	}
	run("CREATE DATABASE " + name)

	config := admin.Copy()
	config.Database = name
	db, err := pgx.ConnectConfig(ctx, config)
	require.NoError(t, err)

	return db, func() {
		_ = db.Close(ctx)
		run("DROP DATABASE " + name + " WITH (FORCE)")
	}
}

func postgresProvider(admin *pgx.ConnConfig) string {
	return fmt.Sprintf(`
provider "cipherstash" {
  database = {
    host     = %q
    port     = %d
    username = %q
    password = %q
    sslmode  = "disable"
  }
}
`, admin.Host, admin.Port, admin.User, admin.Password)
}

// createIndexedTable creates a table with EQL-typed columns and the functional
// index EQL documents for each kind of query, all of which exist in every
// compiled-in version: equality (hash on eq_term), OPE ordering (btree on
// ord_term), ORE ordering (btree on ord_term_ore, which needs the ORE operator
// class) and text match (GIN on match_term).
func createIndexedTable(t rapid.TB, db *pgx.Conn) {
	t.Helper()

	_, err := db.Exec(context.Background(), `
CREATE TABLE encrypted (
  id         bigint PRIMARY KEY,
  email      public.eql_v4_text_eq,
  amount     public.eql_v4_bigint_ord,
  amount_ore public.eql_v4_bigint_ord_ore,
  name       public.eql_v4_text_match
);`+eqlIndexes)
	require.NoError(t, err)
}

const eqlIndexes = `
CREATE INDEX encrypted_email_eq ON encrypted USING hash (eql_v4.eq_term(email));
CREATE INDEX encrypted_amount_ord ON encrypted USING btree (eql_v4.ord_term(amount));
CREATE INDEX encrypted_amount_ore ON encrypted USING btree (eql_v4.ord_term_ore(amount_ore));
CREATE INDEX encrypted_name_match ON encrypted USING gin (eql_v4.match_term(name));`

// handInstall runs a compiled-in installer outside Terraform, as psql -f
// would, installing EQL or reinstalling it over another version.
func handInstall(t rapid.TB, db *pgx.Conn, version string) {
	t.Helper()

	script, err := os.ReadFile(filepath.Join("..", "eql", "bundles", version, "eql-v4-install.sql"))
	require.NoError(t, err)
	_, err = db.PgConn().Exec(context.Background(), "SET search_path = public;\n"+string(script)).ReadAll()
	require.NoError(t, err)
}

func eqlInstalled(t *testing.T, db *pgx.Conn) bool {
	t.Helper()

	var installed bool
	require.NoError(t, db.QueryRow(t.Context(), "SELECT to_regnamespace('eql_v4') IS NOT NULL").Scan(&installed))

	return installed
}

// eqlLeftovers counts the EQL domains and functions in schema public, which
// the upstream uninstaller leaves behind.
func eqlLeftovers(ctx context.Context, t rapid.TB, db *pgx.Conn) int {
	t.Helper()

	var count int
	require.NoError(t, db.QueryRow(ctx, `
SELECT (SELECT count(*) FROM pg_type WHERE typnamespace = 'public'::regnamespace AND typname LIKE 'eql\_v4\_%')
     + (SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'eql\_v4\_%')`).Scan(&count))

	return count
}

func TestCLIPostgresEQLLifecycle(t *testing.T) {
	db, provider := testPostgres(t)
	other, dropOther := createDatabase(t, postgresAdmin(t))
	t.Cleanup(dropOther)
	version := eql.Versions()[0]
	digest, _ := eql.SHA256(version)
	sql := func(db *pgx.Conn, statement string) func() {
		return func() {
			_, err := db.Exec(t.Context(), statement)
			require.NoError(t, err)
		}
	}
	// The marker stands in for a grant, which Terraform destroys before EQL.
	config := func(db *pgx.Conn) string {
		return provider + fmt.Sprintf("resource \"cipherstash_eql_v4\" \"this\" {\n database = %q\n version = %q\n}\n", db.Config().Database, version) +
			"resource \"terraform_data\" \"grant\" {\n input = cipherstash_eql_v4.this.schema\n}\n"
	}
	setVersion := func(reported string) func() {
		return sql(db, "CREATE OR REPLACE FUNCTION eql_v4.version() RETURNS text IMMUTABLE STRICT LANGUAGE sql AS $$SELECT '"+reported+"'$$")
	}
	uninstalled := func(db *pgx.Conn) resource.TestCheckFunc {
		return func(*terraform.State) error {
			if eqlInstalled(t, db) || eqlLeftovers(t.Context(), t, db) != 0 {
				return fmt.Errorf("EQL or its domains and functions in public remain in %s", db.Config().Database)
			}

			return nil
		}
	}
	tc := cliTestCase(t, newServiceFixture(t))
	tc.Steps = []resource.TestStep{
		{
			Config: config(db),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("cipherstash_eql_v4.this", tfjsonpath.New("version"), knownvalue.StringExact(version)),
				statecheck.ExpectKnownValue("cipherstash_eql_v4.this", tfjsonpath.New("sha256"), knownvalue.StringExact(digest)),
				statecheck.ExpectKnownValue("cipherstash_eql_v4.this", tfjsonpath.New("owner"), knownvalue.StringExact(db.Config().User)),
				statecheck.ExpectKnownValue("cipherstash_eql_v4.this", tfjsonpath.New("ore_available"), knownvalue.Bool(true)),
				// Without pgcrypto, the installer creates it in a new extensions schema.
				statecheck.ExpectKnownValue("cipherstash_eql_v4.this", tfjsonpath.New("pgcrypto_schema"), knownvalue.StringExact("extensions")),
			},
		},
		{ResourceName: "cipherstash_eql_v4.this", ImportState: true, ImportStateId: db.Config().Database, ImportStateVerify: true},
		// Without an uninstaller for the version refresh reads, destroy fails
		// while planning, before Terraform destroys the marker.
		{PreConfig: setVersion("go-0.0.0"), Config: provider, ExpectError: regexp.MustCompile(`EQL uninstall refused[\s\S]*reports EQL go-0\.0\.0`)},
		{PreConfig: setVersion(version), Config: config(db), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		// Changing database uninstalls from the old one, then installs in the new one.
		{
			Config:           config(other),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("cipherstash_eql_v4.this", plancheck.ResourceActionDestroyBeforeCreate)}},
			Check: resource.ComposeTestCheckFunc(uninstalled(db), func(*terraform.State) error {
				if !eqlInstalled(t, other) {
					return fmt.Errorf("replacement did not install EQL in the new database")
				}

				return nil
			}),
		},
		{
			PreConfig:   sql(other, "CREATE TABLE encrypted (email public.eql_v4_text_eq)"),
			Config:      provider,
			ExpectError: regexp.MustCompile(`EQL uninstall refused[\s\S]*column email of table encrypted`),
		},
		{PreConfig: sql(other, "DROP TABLE encrypted"), Config: provider, Check: uninstalled(other)},
		{Config: config(db)},
		{
			PreConfig:          sql(db, "DROP SCHEMA eql_v4 CASCADE; DROP SCHEMA eql_v4_internal CASCADE"),
			RefreshState:       true,
			ExpectNonEmptyPlan: true,
			Check: func(s *terraform.State) error {
				if _, ok := s.RootModule().Resources["cipherstash_eql_v4.this"]; ok {
					return fmt.Errorf("refresh kept an installation removed outside Terraform")
				}

				return nil
			},
		},
		{Config: provider},
	}
	resource.UnitTest(t, tc)
	require.False(t, eqlInstalled(t, db))
}

func TestCLIPostgresEQLImport(t *testing.T) {
	db, provider := testPostgres(t)
	version := eql.Versions()[0]
	_, err := db.Exec(t.Context(), "CREATE EXTENSION pgcrypto")
	require.NoError(t, err)
	handInstall(t, db, version)

	resourceConfig := fmt.Sprintf("resource \"cipherstash_eql_v4\" \"this\" {\n database = %q\n version = %q\n}\n", db.Config().Database, version)
	tc := cliTestCase(t, newServiceFixture(t))
	tc.Steps = []resource.TestStep{
		{
			Config:           provider + resourceConfig + fmt.Sprintf("import {\n to = cipherstash_eql_v4.this\n id = %q\n}\n", db.Config().Database),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("cipherstash_eql_v4.this", plancheck.ResourceActionNoop)}},
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("cipherstash_eql_v4.this", tfjsonpath.New("pgcrypto_schema"), knownvalue.StringExact("public")),
				statecheck.ExpectKnownValue("cipherstash_eql_v4.this", tfjsonpath.New("ore_available"), knownvalue.Bool(true)),
			},
		},
		{Config: provider + "removed {\n from = cipherstash_eql_v4.this\n lifecycle {\n destroy = false\n }\n}\n"},
	}
	resource.UnitTest(t, tc)
	require.True(t, eqlInstalled(t, db), "removing the resource from state uninstalled EQL")
}

// TestCLIPostgresEQLUpgradeModel runs Terraform against a model of one
// database's EQL installation while its version changes. Changing version to
// a later release upgrades in place, keeping grants and, when
// allow_index_rebuild is set, the table's functional indexes; it refuses while
// a view depends on EQL, and an earlier version fails to plan. The hand upgrade
// still works: stop managing the installation, reinstall, rebuild the indexes
// and import it. Destroy uninstalls once the table of EQL-typed columns and the
// view are gone, so a trace can install again.
func TestCLIPostgresEQLUpgradeModel(t *testing.T) {
	admin := postgresAdmin(t)
	cliTestCase(t, newServiceFixture(t)) // Pinned CLI and isolated CLI configuration.
	reattach := reattachProvider(t)
	versions := eql.Versions()
	require.GreaterOrEqual(t, len(versions), 2, "no upgrade path to test")

	// Fixed traces cover every upgrade path whatever the random budget. Each
	// installs its first version through Terraform and grants a role access,
	// then for every later version is refused for its indexes and for a
	// dependent view before it upgrades, and fails to plan a downgrade. Each
	// ends by uninstalling, installing its first version again and upgrading
	// to its last by hand.
	var paths [][]string
	for i := range versions {
		for _, next := range versions[i+1:] {
			paths = append(paths, []string{versions[i], next})
		}
	}

	if len(versions) > 2 {
		paths = append(paths, versions)
	}

	for _, path := range paths {
		t.Run(strings.Join(path, " to "), func(t *testing.T) {
			m := newEQLUpgradeModel(t, admin, reattach, path[0])
			defer m.close(t)

			steps := []func(){func() { m.apply(t, path[0]) }, func() { m.grant(t) }}
			for i, next := range path[1:] {
				steps = append(steps,
					func() { m.apply(t, next) },
					func() { m.addView(t) },
					func() { m.toggleRebuild(t) },
					func() { m.dropView(t) },
					func() { m.apply(t, next) },
					func() { m.apply(t, path[i]) },
				)
			}

			last := path[len(path)-1]
			steps = append(steps,
				func() { m.destroy(t) },
				func() { m.dropTable(t) },
				func() { m.destroy(t) },
				func() { m.apply(t, path[0]) },
				func() { m.forget(t) },
				func() { m.handInstall(t, last) },
				func() { m.importExisting(t) },
				func() { m.rebuildIndexes(t) },
				func() { m.apply(t, last) },
			)
			for _, step := range steps {
				step()
				m.check(t)
			}

			require.True(t, m.managed)
			require.True(t, m.indexed)
			require.Equal(t, last, m.state)
		})
	}

	t.Run("generated", func(t *testing.T) {
		rapid.Check(t, func(r *rapid.T) {
			version := rapid.SampledFrom(versions)
			m := newEQLUpgradeModel(r, admin, reattach, version.Draw(r, "configured version"))
			defer m.close(r)

			whenInstalled := func(action func(rapid.TB)) func(*rapid.T) {
				return func(r *rapid.T) {
					if m.installed == "" {
						r.Skip("EQL is not installed") // Before any draw, so rapid draws another action.
					}

					action(r)
				}
			}
			r.Repeat(map[string]func(*rapid.T){
				"apply":          func(r *rapid.T) { m.apply(r, version.Draw(r, "version")) },
				"toggle rebuild": func(r *rapid.T) { m.toggleRebuild(r) },
				"hand install":   func(r *rapid.T) { m.handInstall(r, version.Draw(r, "version")) },
				"refresh":        func(r *rapid.T) { m.refresh(r) },
				"import":         func(r *rapid.T) { m.importExisting(r) },
				"forget":         func(r *rapid.T) { m.forget(r) },
				"destroy":        func(r *rapid.T) { m.destroy(r) },
				"drop table":     func(r *rapid.T) { m.dropTable(r) },
				"grant":          whenInstalled(m.grant),
				"add view":       whenInstalled(m.addView),
				"drop view":      func(r *rapid.T) { m.dropView(r) },
				"rebuild indexes": func(r *rapid.T) {
					if m.installed == "" || m.indexed || !m.table {
						r.Skip("no dropped indexes") // Before any draw, so rapid draws another action.
					}

					m.rebuildIndexes(r)
				},
				"": func(r *rapid.T) { m.check(r) },
			})
		})
	})
}

// eqlUpgradeModel is one database, one Terraform working directory, and what
// the model predicts for them.
type eqlUpgradeModel struct {
	ctx      context.Context //nolint:containedctx // One deadline bounds every command in a trace.
	cancel   context.CancelFunc
	tf       *tfexec.Terraform
	reattach *tfexec.ReattachOption
	db       *pgx.Conn
	drop     func()
	dir      string
	provider string
	role     string // a role that grants give access to EQL

	installed    string // eql_v4.version(), or empty before any installation
	managed      bool   // whether Terraform state holds the installation
	state        string // the version in Terraform state while managed
	config       string // the version in the resource block
	rebuild      bool   // allow_index_rebuild in the resource block
	stateRebuild bool   // allow_index_rebuild in Terraform state while managed
	table        bool   // whether the EQL-typed table exists
	indexed      bool   // whether its EQL functional indexes exist
	granted      bool   // whether role has USAGE on both EQL schemas and default privileges in one
	view         bool   // whether a view that calls EQL exists
}

const eqlAddress = "cipherstash_eql_v4.this"

func newEQLUpgradeModel(t rapid.TB, admin *pgx.ConnConfig, reattach *tfexec.ReattachOption, config string) *eqlUpgradeModel {
	t.Helper()

	dir, err := os.MkdirTemp("", "cipherstash-eql-upgrade-")
	require.NoError(t, err)
	binary, err := exec.LookPath("terraform")
	require.NoError(t, err)
	tf, err := tfexec.NewTerraform(dir, binary)
	require.NoError(t, err)
	db, dropDatabase := createDatabase(t, admin)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	role := db.Config().Database + "_app"
	_, err = db.Exec(ctx, "CREATE ROLE "+role)
	require.NoError(t, err)
	drop := func() {
		dropDatabase()
		conn, err := pgx.ConnectConfig(context.Background(), admin)
		require.NoError(t, err)
		defer func() { _ = conn.Close(context.Background()) }()

		_, err = conn.Exec(context.Background(), "DROP ROLE "+role)
		require.NoError(t, err)
	}
	m := &eqlUpgradeModel{ctx: ctx, cancel: cancel, tf: tf, reattach: reattach, db: db, drop: drop, dir: dir, provider: postgresProvider(admin), role: role, config: config}
	m.write(t, "")
	require.NoError(t, tf.Init(ctx, reattach))

	return m
}

func (m *eqlUpgradeModel) close(t rapid.TB) {
	m.cancel()
	m.drop()
	assert.NoError(t, os.RemoveAll(m.dir))
}

func (m *eqlUpgradeModel) write(t rapid.TB, block string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(m.dir, "main.tf"), []byte(m.provider+block), 0o600))
}

func (m *eqlUpgradeModel) writeResource(t rapid.TB) {
	t.Helper()
	m.write(t, fmt.Sprintf("resource \"cipherstash_eql_v4\" \"this\" {\n database = %q\n version = %q\n allow_index_rebuild = %t\n}\n", m.db.Config().Database, m.config, m.rebuild))
}

// apply configures version and applies. Planning refreshes first, so a
// managed installation's state takes the installed version before the
// configured version is compared with it.
func (m *eqlUpgradeModel) apply(t rapid.TB, version string) {
	t.Helper()
	m.config = version
	m.writeResource(t)
	upgrade := m.managed && version != m.installed
	_, err := m.tf.Plan(m.ctx, m.reattach, tfexec.Out("next.tfplan"))
	if upgrade && !eql.Later(m.installed, version) {
		require.ErrorContains(t, err, "EQL downgrades are not supported")

		return // A failed plan saves nothing, including the refresh.
	}

	require.NoError(t, err)
	err = m.tf.Apply(m.ctx, m.reattach, tfexec.DirOrPlan("next.tfplan"))
	switch {
	case upgrade && m.view:
		require.ErrorContains(t, err, "view eql_release")
		m.state = m.installed // A failed Update keeps the refreshed state.
	case upgrade && m.indexed && !m.rebuild:
		require.ErrorContains(t, err, "allow_index_rebuild = true")
		m.state = m.installed
	case upgrade:
		// Grants and indexes survive the reinstall.
		require.NoError(t, err)
		m.installed, m.state, m.stateRebuild = version, version, m.rebuild
	case m.managed:
		require.NoError(t, err)
		m.state, m.stateRebuild = m.installed, m.rebuild
	case m.installed != "":
		require.ErrorContains(t, err, "EQL installation refused") // Create never adopts.
	default:
		require.NoError(t, err)
		m.installed, m.managed, m.state, m.stateRebuild = version, true, version, m.rebuild
		createIndexedTable(t, m.db)
		m.table, m.indexed = true, true
	}
}

// toggleRebuild flips allow_index_rebuild and applies the configured version.
func (m *eqlUpgradeModel) toggleRebuild(t rapid.TB) {
	t.Helper()
	m.rebuild = !m.rebuild
	m.apply(t, m.config)
}

func (m *eqlUpgradeModel) grant(t rapid.TB) {
	t.Helper()
	_, err := m.db.Exec(m.ctx, fmt.Sprintf("GRANT USAGE ON SCHEMA eql_v4, eql_v4_internal TO %[1]s; ALTER DEFAULT PRIVILEGES IN SCHEMA eql_v4 GRANT EXECUTE ON FUNCTIONS TO %[1]s", m.role))
	require.NoError(t, err)
	m.granted = true
}

func (m *eqlUpgradeModel) addView(t rapid.TB) {
	t.Helper()
	_, err := m.db.Exec(m.ctx, "CREATE OR REPLACE VIEW eql_release AS SELECT eql_v4.version() AS version")
	require.NoError(t, err)
	m.view = true
}

func (m *eqlUpgradeModel) dropView(t rapid.TB) {
	t.Helper()
	_, err := m.db.Exec(m.ctx, "DROP VIEW IF EXISTS eql_release")
	require.NoError(t, err)
	m.view = false
}

func (m *eqlUpgradeModel) handInstall(t rapid.TB, version string) {
	t.Helper()
	handInstall(t, m.db, version)
	if m.installed == "" {
		createIndexedTable(t, m.db)
		m.table, m.indexed = true, true
	} else {
		// The installer drops both EQL schemas with CASCADE, taking every
		// index, view and grant on them, even when reinstalling the same version.
		m.indexed, m.view, m.granted = false, false, false
	}

	m.installed = version
}

// rebuildIndexes re-creates the indexes a reinstall dropped, the last step of
// a hand upgrade.
func (m *eqlUpgradeModel) rebuildIndexes(t rapid.TB) {
	t.Helper()
	_, err := m.db.Exec(m.ctx, eqlIndexes)
	require.NoError(t, err)
	m.indexed = true
}

func (m *eqlUpgradeModel) refresh(t rapid.TB) {
	t.Helper()
	m.writeResource(t)
	require.NoError(t, m.tf.Apply(m.ctx, m.reattach, tfexec.RefreshOnly(true)))
	if m.managed {
		m.state = m.installed
	}
}

func (m *eqlUpgradeModel) importExisting(t rapid.TB) {
	t.Helper()
	m.writeResource(t)
	err := m.tf.Import(m.ctx, eqlAddress, m.db.Config().Database, m.reattach)
	switch {
	case m.managed:
		require.ErrorContains(t, err, "Resource already managed")
	case m.installed == "":
		require.ErrorContains(t, err, "EQL is not installed")
	default:
		require.NoError(t, err)
		m.managed, m.state, m.stateRebuild = true, m.installed, false // Import cannot know the configuration.
	}
}

// destroy removes the resource block and applies. Destroy uninstalls EQL
// unless a column still uses an EQL domain or a view depends on EQL.
func (m *eqlUpgradeModel) destroy(t rapid.TB) {
	t.Helper()
	m.write(t, "")
	err := m.tf.Apply(m.ctx, m.reattach)
	switch {
	case !m.managed:
		require.NoError(t, err)
	case m.table || m.view:
		require.ErrorContains(t, err, "EQL uninstall refused")
		m.state = m.installed // Planning refreshed, and a failed Delete keeps that state.
	default:
		require.NoError(t, err)
		m.installed, m.managed, m.state, m.indexed, m.granted = "", false, "", false, false
	}
}

func (m *eqlUpgradeModel) dropTable(t rapid.TB) {
	t.Helper()
	_, err := m.db.Exec(m.ctx, "DROP TABLE IF EXISTS encrypted")
	require.NoError(t, err)
	m.table, m.indexed = false, false
}

// forget stops managing the installation without changing the database.
func (m *eqlUpgradeModel) forget(t rapid.TB) {
	t.Helper()
	m.write(t, "removed {\n from = "+eqlAddress+"\n lifecycle {\n destroy = false\n }\n}\n")
	require.NoError(t, m.tf.Apply(m.ctx, m.reattach))
	m.managed, m.state = false, ""
}

func (m *eqlUpgradeModel) check(t rapid.TB) {
	t.Helper()

	installed := ""
	var exists bool
	require.NoError(t, m.db.QueryRow(m.ctx, "SELECT to_regnamespace('eql_v4') IS NOT NULL").Scan(&exists))
	if exists {
		require.NoError(t, m.db.QueryRow(m.ctx, "SELECT eql_v4.version()").Scan(&installed))
	}

	require.Equal(t, m.installed, installed, "installed version differs from the model")
	if m.installed == "" {
		require.Zero(t, eqlLeftovers(m.ctx, t, m.db), "EQL domains or functions remain in public without EQL")
	}

	var granted, view bool
	require.NoError(t, m.db.QueryRow(m.ctx, `
SELECT CASE WHEN to_regnamespace('eql_v4') IS NULL THEN false
            ELSE has_schema_privilege($1, 'eql_v4', 'USAGE') AND has_schema_privilege($1, 'eql_v4_internal', 'USAGE')
              AND EXISTS (SELECT FROM pg_default_acl WHERE defaclnamespace = to_regnamespace('eql_v4')) END,
       to_regclass('public.eql_release') IS NOT NULL`, m.role).Scan(&granted, &view))
	require.Equal(t, m.granted, granted, "grants differ from the model")
	require.Equal(t, m.view, view, "view differs from the model")

	// Terraform never touches user tables or indexes; only a reinstall drops
	// the indexes. Index operator classes come from pg_index, because
	// pg_get_indexdef omits a default one, such as record_ops bound in place of
	// the ORE operator class.
	rows, err := m.db.Query(m.ctx, `
SELECT 'column ' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod)
FROM pg_attribute a
WHERE a.attrelid = to_regclass('public.encrypted') AND a.attnum > 0 AND NOT a.attisdropped
UNION ALL
SELECT 'index ' || i.relname || ' ' || am.amname || ' ' || oc.opcname
FROM pg_index x
JOIN pg_class i ON i.oid = x.indexrelid
JOIN pg_am am ON am.oid = i.relam
JOIN pg_opclass oc ON oc.oid = x.indclass[0]
WHERE x.indrelid = to_regclass('public.encrypted')`)
	require.NoError(t, err)
	objects, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	var want []string
	if m.table {
		want = append(want, "column id bigint", "column email eql_v4_text_eq", "column amount eql_v4_bigint_ord",
			"column amount_ore eql_v4_bigint_ord_ore", "column name eql_v4_text_match", "index encrypted_pkey btree int8_ops")
	}

	if m.indexed {
		want = append(want, "index encrypted_email_eq hash text_ops", "index encrypted_amount_ord btree bytea_ops",
			"index encrypted_amount_ore btree ore_block_v2_operator_class", "index encrypted_name_match gin array_ops")
	}

	require.ElementsMatch(t, want, objects, "table or indexes differ from the model")

	s, err := m.tf.Show(m.ctx, m.reattach)
	require.NoError(t, err)
	if !m.managed {
		require.True(t, s.Values == nil || len(s.Values.RootModule.Resources) == 0, "Terraform manages an installation the model does not")

		return
	}

	require.NotNil(t, s.Values)
	require.Len(t, s.Values.RootModule.Resources, 1)
	attributes := s.Values.RootModule.Resources[0].AttributeValues
	require.Equal(t, m.db.Config().Database, attributes["id"])
	require.Equal(t, m.state, attributes["version"], "state version differs from the model")
	require.Equal(t, m.stateRebuild, attributes["allow_index_rebuild"], "state allow_index_rebuild differs from the model")
	require.Equal(t, true, attributes["ore_available"])

	if m.config == m.state && m.state == m.installed && m.rebuild == m.stateRebuild {
		m.writeResource(t)
		changes, err := m.tf.Plan(m.ctx, m.reattach)
		require.NoError(t, err)
		require.False(t, changes, "an up-to-date installation plans changes")
	}
}
