package provider

import (
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"os"
	"strings"
	"testing"

	control "github.com/cipherstash/terraform-provider-cipherstash/internal/stack/manage"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/stretchr/testify/require"
)

// This test creates and destroys live objects. It is never enabled by merely
// having a Development credential in the environment.
func TestAccActorAndClientLifecycle(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("live lifecycle requires TF_ACC=1 and coordinated workspace access")
	}

	crn := os.Getenv("TF_ACC_CRN")
	workspace := os.Getenv("TF_ACC_WORKSPACE_ID")
	require.True(t, workspace != "" && crn != "" && strings.HasSuffix(crn, ":"+workspace) && os.Getenv("CIPHERSTASH_ACCESS_KEY") != "", "set TF_ACC_WORKSPACE_ID, a matching TF_ACC_CRN and CIPHERSTASH_ACCESS_KEY for the explicitly approved acceptance workspace")
	p := New()
	t.Cleanup(p.Close)
	var schema frameworkprovider.SchemaResponse
	p.Schema(context.Background(), frameworkprovider.SchemaRequest{}, &schema)
	config := tfsdk.State{Schema: schema.Schema}
	noErrors(t, config.Set(context.Background(), providerModel{CRN: types.StringValue(crn), AccessKey: types.StringNull()}))
	var configured frameworkprovider.ConfigureResponse
	p.Configure(context.Background(), frameworkprovider.ConfigureRequest{Config: tfsdk.Config{Schema: schema.Schema, Raw: config.Raw}}, &configured)
	noErrors(t, configured.Diagnostics)
	api, err := clientFromProviderData(configured.ResourceData)
	require.NoError(t, err)
	inventory := func() (map[string]bool, error) {
		ids := map[string]bool{}
		cursor := ""
		for {
			page, err := api.ListActors(context.Background(), control.ListActorsOptions{Limit: 100, Cursor: cursor})
			if err != nil {
				return nil, err
			}

			for _, actor := range page.Items {
				ids["actor:"+actor.ID] = true
			}

			if page.NextCursor == "" {
				break
			}

			cursor = page.NextCursor
		}

		keys, err := api.ListAccessKeys(context.Background())
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			ids["key:"+key.ID] = true
		}

		clients, err := api.ListClients(context.Background(), control.ListClientsOptions{})
		if err != nil {
			return nil, err
		}

		for _, client := range clients {
			ids["client:"+client.ID] = true
		}

		return ids, nil
	}
	baseline, err := inventory()
	if err != nil {
		require.FailNowf(t, "cannot record baseline", "%s", operationError(err))
	}

	name := "tf-acc-" + strings.ToLower(rand.Text()[:12])
	configuration := func(suffix, kind, role string) string {
		return fmt.Sprintf(`
provider "cipherstash" { crn = %q }
resource "cipherstash_actor" "test" {
  name = %q
  kind = %q
  role = %q
  token_expiry = 900
}
resource "cipherstash_client" "test" {
  name = %q
  description = %q
}
data "cipherstash_client" "test" {
  id = cipherstash_client.test.id
}
`, crn, name+suffix, kind, role, name+suffix, "Terraform acceptance "+suffix)
	}
	actorIDs := map[string]bool{}
	clientIDs := map[string]bool{}
	var actorSecret, clientSecret string
	check := func(replaced bool) resource.TestCheckFunc {
		return func(state *terraform.State) error {
			actor := state.RootModule().Resources["cipherstash_actor.test"].Primary
			client := state.RootModule().Resources["cipherstash_client.test"].Primary
			lookup := state.RootModule().Resources["data.cipherstash_client.test"].Primary
			if lookup.ID != client.ID || lookup.Attributes["name"] != client.Attributes["name"] || lookup.Attributes["description"] != client.Attributes["description"] || lookup.Attributes["keyset_ids.#"] != "1" {
				return fmt.Errorf("data source did not read the created client's metadata and grant")
			}

			if err := resource.TestCheckTypeSetElemAttrPair("data.cipherstash_client.test", "keyset_ids.*", "cipherstash_client.test", "keyset_id")(state); err != nil {
				return err
			}

			if actor.ID == "" || client.ID == "" || actor.Attributes["key_id"] == "" || client.Attributes["keyset_id"] == "" {
				return fmt.Errorf("created resource metadata is incomplete")
			}

			a, c := actor.Attributes["access_key"], client.Attributes["client_key"]
			if a == "" || c == "" {
				return fmt.Errorf("creation secrets are missing from state")
			}

			if replaced {
				if actorIDs[actor.ID] || clientIDs[client.ID] || a == actorSecret || c == clientSecret {
					return fmt.Errorf("replacement did not rotate identities and secrets")
				}
			} else if actorSecret != "" && (a != actorSecret || c != clientSecret) {
				return fmt.Errorf("refresh changed creation secrets")
			}

			actorIDs[actor.ID], clientIDs[client.ID] = true, true
			actorSecret, clientSecret = a, c

			return nil
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cipherstash": func() (tfprotov6.ProviderServer, error) {
				provider := New()
				t.Cleanup(provider.Close)

				return Protocol6(provider), nil
			},
		},
		CheckDestroy: func(*terraform.State) error {
			after, err := inventory()
			if err != nil {
				return fmt.Errorf("cannot verify cleanup: %s", operationError(err))
			}

			if !maps.Equal(baseline, after) {
				return fmt.Errorf("actor/access-key/client identifiers differ from the pre-test baseline; inspect inventory before another run")
			}

			t.Log("actor, access-key and client identifiers match the pre-test baseline")

			return nil
		},
		Steps: []resource.TestStep{
			{Config: configuration("", "app", "member"), Check: check(false)},
			{Config: configuration("", "app", "member"), Check: check(false)},
			{ResourceName: "cipherstash_actor.test", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"access_key", "token_expiry"}},
			{
				ResourceName: "cipherstash_client.test", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"client_key"},
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					client := s.RootModule().Resources["cipherstash_client.test"].Primary
					return client.ID + "/" + client.Attributes["keyset_id"], nil
				},
			},
			{Config: configuration("-v2", "agent", "control"), Check: check(true)},
		},
	})
}
