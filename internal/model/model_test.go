package model

import "testing"

func TestDefaultProfilesUseDocumentedIDs(t *testing.T) {
	profiles := DefaultProfiles()
	want := []ProfileID{
		ProfileBaseline,
		ProfileStrict,
		ProfileSocketFirewall,
		ProfileVeracodePackageFirewall,
		ProfilePrivateRegistry,
	}

	if len(profiles) != len(want) {
		t.Fatalf("profiles len = %d, want %d", len(profiles), len(want))
	}
	for i, profile := range profiles {
		if profile.ID != want[i] {
			t.Fatalf("profiles[%d].ID = %q, want %q", i, profile.ID, want[i])
		}
	}
}

func TestEmptyReportCollectionsAreNonNil(t *testing.T) {
	inventory := EmptyInventory()
	policy := EmptyPolicy()

	if inventory.Ecosystems == nil {
		t.Fatal("Inventory.Ecosystems is nil")
	}
	if inventory.PackageManagers == nil {
		t.Fatal("Inventory.PackageManagers is nil")
	}
	if inventory.Manifests == nil {
		t.Fatal("Inventory.Manifests is nil")
	}
	if inventory.Lockfiles == nil {
		t.Fatal("Inventory.Lockfiles is nil")
	}
	if inventory.CIWorkflows == nil {
		t.Fatal("Inventory.CIWorkflows is nil")
	}
	if inventory.DependencyBots == nil {
		t.Fatal("Inventory.DependencyBots is nil")
	}
	if inventory.PackageManagerConfigFiles == nil {
		t.Fatal("Inventory.PackageManagerConfigFiles is nil")
	}
	if policy.Profiles == nil {
		t.Fatal("Policy.Profiles is nil")
	}
	if policy.Rules.Enabled == nil {
		t.Fatal("Policy.Rules.Enabled is nil")
	}
	if policy.Rules.Disabled == nil {
		t.Fatal("Policy.Rules.Disabled is nil")
	}
	if policy.Suppressions == nil {
		t.Fatal("Policy.Suppressions is nil")
	}
}
