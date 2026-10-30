package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	control "github.com/cipherstash/terraform-provider-cipherstash/internal/stack/manage"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
)

const fixtureTimestamp = "2026-10-26T00:00:00Z"

// Public deterministic permutations in recipher 0.3.1's generated v1 format.
// These are structural test values, not registered CipherStash credentials.
func fixtureClientKey(seed string) string {
	hash := sha256.Sum256([]byte(seed))
	rng := rand.New(rand.NewPCG(binary.LittleEndian.Uint64(hash[:8]), binary.LittleEndian.Uint64(hash[8:16])))
	key := map[string]map[string][]int{}
	for _, name := range []string{"p1", "p2_from", "p2_to", "p3"} {
		size := 16
		if name == "p3" {
			size = 33
		}
		key[name] = map[string][]int{"permutation": rng.Perm(size)}
	}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	encoded, err := mode.Marshal(key)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

// Management models are not wire types; use the service's snake_case fields.
func keysetJSON(k control.Keyset) map[string]any {
	return map[string]any{"id": k.ID, "name": k.Name, "description": k.Description, "is_disabled": k.IsDisabled, "is_default": k.IsDefault}
}

// This fixture models service inventory only. Terraform owns plans, state,
// replacement and recovery in the CLI tests. It is not evidence of live API behavior.
type serviceFixture struct {
	t                 *testing.T
	mu                sync.Mutex
	next              int
	actors            []control.Actor
	keys              []control.AccessKeyMetadata
	clients           []control.EncryptionClient
	keysets           []control.Keyset
	secrets           map[string]string
	requests          []string
	mutations         []string
	faults            []serviceFault
	pageSize          int
	repeatCursor      bool
	failActorMetadata bool
}

type serviceFault struct {
	path       string
	skip       int
	afterWrite bool
	status     int
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	f := &serviceFixture{
		t: t, secrets: map[string]string{}, pageSize: 1,
		keysets: []control.Keyset{
			{ID: keysetID, Name: "default", Description: "Default", IsDefault: true},
			{ID: tenantKeysetID, Name: "external", Description: "Worker owned"},
		},
	}
	t.Cleanup(func() {
		f.edit(func() {
			assert.Empty(t, f.faults, "fixture faults were never exercised")
		})
	})

	return f
}

func (f *serviceFixture) newID() string {
	f.next++
	return fmt.Sprintf("aaaaaaaa-bbbb-4ccc-8ddd-%012x", f.next)
}

// edit is also used by PreConfig to simulate out-of-band service changes.
func (f *serviceFixture) edit(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()

	fn()
}

func (f *serviceFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests = append(f.requests, r.URL.Path)
	var input struct {
		Name         *string `json:"name"`
		Description  *string `json:"description"`
		Kind         string  `json:"kind"`
		Role         string  `json:"role"`
		TokenExpiry  *int64  `json:"tokenExpiry"`
		ClientID     string  `json:"client_id"`
		KeysetID     string  `json:"keyset_id"`
		ShowDisabled bool    `json:"show_disabled"`
	}
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if !assert.NoError(f.t, decoder.Decode(&input), "unexpected fixture request JSON for %s", r.URL.Path) {
			http.Error(w, "invalid fixture request", http.StatusBadRequest)
			return
		}
	}

	var fault *serviceFault
	for i := range f.faults {
		if f.faults[i].path == r.URL.Path {
			if f.faults[i].skip > 0 {
				f.faults[i].skip--
				break
			}

			v := f.faults[i]
			fault = &v
			f.faults = slices.Delete(f.faults, i, i+1)
			break
		}
	}

	if fault != nil && !fault.afterWrite {
		http.Error(w, "fixture-upstream-secret", fault.status)
		return
	}

	var body any = struct{}{}
	mutation := false
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/actors":
		if input.Name == nil || input.Kind == "" || input.Role == "" {
			assert.Fail(f.t, "create actor omitted required fields")
			http.Error(w, "invalid fixture actor", 400)

			return
		}

		if slices.ContainsFunc(f.actors, func(a control.Actor) bool { return a.Name == *input.Name }) {
			http.Error(w, "duplicate actor name", http.StatusConflict)
			return
		}

		id := input.Kind + "-" + f.newID()
		actor := control.Actor{ID: id, Name: *input.Name, Kind: control.ActorKind(input.Kind), CreatedAt: fixtureTimestamp}
		f.actors = append(f.actors, actor)
		f.keys = append(f.keys, control.AccessKeyMetadata{ID: "key-" + id, Name: actor.Name, Role: control.Role(input.Role), CreatedAt: fixtureTimestamp})
		f.secrets[id] = "CSAK" + id + ".fixture-secret"
		body = map[string]any{"actorId": id, "name": actor.Name, "kind": actor.Kind, "role": input.Role, "createdAt": actor.CreatedAt, "accessKey": f.secrets[id]}
		if f.failActorMetadata {
			f.faults = append(f.faults, serviceFault{path: "/api/access-keys", status: 500})
			f.failActorMetadata = false
		}

		mutation = true
	case r.Method == http.MethodGet && r.URL.Path == "/api/actors":
		start := 0
		if cursor := r.URL.Query().Get("cursor"); cursor != "" {
			var err error
			start, err = strconv.Atoi(cursor)
			if err != nil || start < 0 || start > len(f.actors) {
				assert.Failf(f.t, "unexpected actor cursor", "%q", cursor)
				http.Error(w, "bad cursor", 400)

				return
			}
		}

		end := min(start+f.pageSize, len(f.actors))
		page := control.ActorPage{Items: append([]control.Actor{}, f.actors[start:end]...)}
		if end < len(f.actors) {
			page.NextCursor = strconv.Itoa(end)
		}

		if f.repeatCursor {
			page.NextCursor = "0"
		}

		body = page
	case r.Method == http.MethodGet && r.URL.Path == "/api/access-keys":
		body = append([]control.AccessKeyMetadata{}, f.keys...)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/actors/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/actors/")
		f.actors = slices.DeleteFunc(f.actors, func(a control.Actor) bool { return a.ID == id })
		f.keys = slices.DeleteFunc(f.keys, func(k control.AccessKeyMetadata) bool { return k.ID == "key-"+id })
		mutation = true
	case r.Method == http.MethodPost && r.URL.Path == "/create-client":
		if input.Name == nil || input.Description == nil {
			assert.Fail(f.t, "create client omitted metadata")
			http.Error(w, "invalid fixture client", 400)

			return
		}

		id := f.newID()
		f.clients = append(f.clients, control.EncryptionClient{ID: id, Name: *input.Name, Description: *input.Description, KeysetIDs: []string{keysetID}})
		f.secrets[id] = fixtureClientKey(id)
		body = map[string]any{"id": id, "name": *input.Name, "description": *input.Description, "dataset_id": keysetID, "client_key": f.secrets[id]}
		mutation = true
	case r.Method == http.MethodPost && r.URL.Path == "/list-clients":
		items := []map[string]any{}
		for _, c := range f.clients {
			items = append(items, map[string]any{"id": c.ID, "name": c.Name, "description": c.Description, "keyset_id": append([]string{}, c.KeysetIDs...)})
		}

		body = items
	case r.Method == http.MethodPost && r.URL.Path == "/delete-client":
		f.clients = slices.DeleteFunc(f.clients, func(c control.EncryptionClient) bool { return c.ID == input.ClientID })
		mutation = true
	case r.Method == http.MethodPost && r.URL.Path == "/create-keyset":
		if input.Name == nil || input.Description == nil {
			assert.Fail(f.t, "create keyset omitted metadata")
			http.Error(w, "invalid fixture keyset", 400)

			return
		}

		k := control.Keyset{ID: f.newID(), Name: *input.Name, Description: *input.Description}
		f.keysets = append(f.keysets, k)
		body, mutation = keysetJSON(k), true
	case r.Method == http.MethodPost && r.URL.Path == "/list-keysets":
		items := []map[string]any{}
		for _, k := range f.keysets {
			if input.ShowDisabled || !k.IsDisabled {
				items = append(items, keysetJSON(k))
			}
		}

		body = items
	case r.Method == http.MethodPost && (r.URL.Path == "/modify-keyset" || r.URL.Path == "/enable-keyset" || r.URL.Path == "/disable-keyset"):
		i := slices.IndexFunc(f.keysets, func(k control.Keyset) bool { return k.ID == input.KeysetID })
		if i < 0 {
			http.Error(w, "keyset absent", 404)
			return
		}

		switch r.URL.Path {
		case "/modify-keyset":
			if input.Name != nil {
				f.keysets[i].Name = *input.Name
			}

			if input.Description != nil {
				f.keysets[i].Description = *input.Description
			}
		case "/enable-keyset":
			f.keysets[i].IsDisabled = false
		case "/disable-keyset":
			f.keysets[i].IsDisabled = true
		}

		mutation = true
	case r.Method == http.MethodPost && (r.URL.Path == "/grant-keyset" || r.URL.Path == "/revoke-keyset"):
		i := slices.IndexFunc(f.clients, func(c control.EncryptionClient) bool { return c.ID == input.ClientID })
		if i < 0 {
			http.Error(w, "client absent", 404)
			return
		}

		if r.URL.Path == "/grant-keyset" {
			if !slices.Contains(f.clients[i].KeysetIDs, input.KeysetID) {
				f.clients[i].KeysetIDs = append(f.clients[i].KeysetIDs, input.KeysetID)
			}
		} else {
			f.clients[i].KeysetIDs = slices.DeleteFunc(f.clients[i].KeysetIDs, func(id string) bool { return id == input.KeysetID })
		}

		mutation = true
	default:
		assert.Failf(f.t, "unexpected fixture endpoint", "%s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected fixture endpoint", 500)

		return
	}

	if mutation {
		f.mutations = append(f.mutations, r.URL.Path)
	}

	if fault != nil {
		assert.True(f.t, mutation, "after-write fault targeted a read")
		http.Error(w, "fixture-upstream-secret", fault.status)

		return
	}

	if r.Method == http.MethodPost && r.URL.Path == "/api/actors" {
		w.WriteHeader(http.StatusCreated)
	}

	assert.NoError(f.t, json.NewEncoder(w).Encode(body), "fixture response failed")
}
