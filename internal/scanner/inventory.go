package scanner

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
)

type inventoryMatch struct {
	kind           string
	name           string
	ecosystem      string
	packageManager string
}

var ignoredDirectories = map[string]struct{}{
	".cache":        {},
	".git":          {},
	".mypy_cache":   {},
	".next":         {},
	".nuxt":         {},
	".parcel-cache": {},
	".pytest_cache": {},
	".ruff_cache":   {},
	".tox":          {},
	".turbo":        {},
	".venv":         {},
	"__pycache__":   {},
	"build":         {},
	"coverage":      {},
	"dist":          {},
	"env":           {},
	"node_modules":  {},
	"target":        {},
	"vendor":        {},
	"venv":          {},
}

func inventoryFor(target string) (model.Inventory, []model.Warning) {
	inventory := model.EmptyInventory()
	warnings := []model.Warning{}

	err := filepath.WalkDir(target, func(path string, entry fs.DirEntry, err error) error {
		rel := relativePath(target, path)
		if err != nil {
			warnings = append(warnings, model.Warning{Path: rel, Message: err.Error()})
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if entry.IsDir() {
			if rel != "." && shouldIgnoreDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		match, ok := classifyInventoryPath(rel)
		if !ok {
			return nil
		}
		name := match.name
		if name == "" {
			name = filepath.ToSlash(filepath.Base(rel))
		}

		item := model.InventoryItem{
			ID:             inventoryItemID(match.kind, rel),
			Name:           name,
			Kind:           match.kind,
			Ecosystem:      match.ecosystem,
			PackageManager: match.packageManager,
			Locations:      []model.Location{{Path: rel}},
		}
		addInventoryItem(&inventory, item)
		return nil
	})
	if err != nil {
		warnings = append(warnings, model.Warning{Path: ".", Message: err.Error()})
	}

	populateInventorySummaries(&inventory)
	sortWarnings(warnings)
	return inventory, warnings
}

func shouldIgnoreDirectory(name string) bool {
	_, ok := ignoredDirectories[name]
	return ok
}

func classifyInventoryPath(path string) (inventoryMatch, bool) {
	slashPath := filepath.ToSlash(path)
	base := filepath.Base(slashPath)

	if match, ok := classifySpecialPath(slashPath); ok {
		return match, true
	}
	if match, ok := ciWorkflowFiles[base]; ok {
		return match, true
	}
	if match, ok := dependencyBotFiles[base]; ok {
		return match, true
	}
	if match, ok := manifestFiles[base]; ok {
		return match, true
	}
	if match, ok := lockfiles[base]; ok {
		return match, true
	}
	if match, ok := packageManagerConfigFiles[base]; ok {
		return match, true
	}
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return inventoryMatch{kind: "manifest", name: base, ecosystem: "python", packageManager: "pip"}, true
	}

	return inventoryMatch{}, false
}

func classifySpecialPath(path string) (inventoryMatch, bool) {
	switch {
	case strings.HasPrefix(path, ".github/workflows/") && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")):
		return inventoryMatch{kind: "ci_workflow", name: filepath.Base(path)}, true
	case path == ".github/dependabot.yml" || path == ".github/dependabot.yaml":
		return inventoryMatch{kind: "dependency_bot", name: filepath.Base(path)}, true
	case path == ".circleci/config.yml":
		return inventoryMatch{kind: "ci_workflow", name: "config.yml"}, true
	case path == ".cargo/config" || path == ".cargo/config.toml":
		return inventoryMatch{kind: "package_manager_config_file", name: filepath.Base(path), ecosystem: "rust", packageManager: "cargo"}, true
	}
	return inventoryMatch{}, false
}

var manifestFiles = map[string]inventoryMatch{
	"Cargo.toml":          {kind: "manifest", ecosystem: "rust", packageManager: "cargo"},
	"Gemfile":             {kind: "manifest", ecosystem: "ruby", packageManager: "bundler"},
	"Pipfile":             {kind: "manifest", ecosystem: "python", packageManager: "pipenv"},
	"build.gradle":        {kind: "manifest", ecosystem: "java", packageManager: "gradle"},
	"build.gradle.kts":    {kind: "manifest", ecosystem: "java", packageManager: "gradle"},
	"composer.json":       {kind: "manifest", ecosystem: "php", packageManager: "composer"},
	"go.mod":              {kind: "manifest", ecosystem: "go", packageManager: "go"},
	"package.json":        {kind: "manifest", ecosystem: "node", packageManager: "npm"},
	"pom.xml":             {kind: "manifest", ecosystem: "java", packageManager: "maven"},
	"pyproject.toml":      {kind: "manifest", ecosystem: "python", packageManager: "python"},
	"settings.gradle":     {kind: "manifest", ecosystem: "java", packageManager: "gradle"},
	"settings.gradle.kts": {kind: "manifest", ecosystem: "java", packageManager: "gradle"},
	"setup.cfg":           {kind: "manifest", ecosystem: "python", packageManager: "setuptools"},
	"setup.py":            {kind: "manifest", ecosystem: "python", packageManager: "setuptools"},
}

var ciWorkflowFiles = map[string]inventoryMatch{
	".gitlab-ci.yml":      {kind: "ci_workflow"},
	"Jenkinsfile":         {kind: "ci_workflow"},
	"azure-pipelines.yml": {kind: "ci_workflow"},
}

var dependencyBotFiles = map[string]inventoryMatch{
	".renovaterc":      {kind: "dependency_bot"},
	".renovaterc.json": {kind: "dependency_bot"},
	".renovaterc.yaml": {kind: "dependency_bot"},
	"renovate.json":    {kind: "dependency_bot"},
}

var lockfiles = map[string]inventoryMatch{
	"Cargo.lock":          {kind: "lockfile", ecosystem: "rust", packageManager: "cargo"},
	"Gemfile.lock":        {kind: "lockfile", ecosystem: "ruby", packageManager: "bundler"},
	"Pipfile.lock":        {kind: "lockfile", ecosystem: "python", packageManager: "pipenv"},
	"composer.lock":       {kind: "lockfile", ecosystem: "php", packageManager: "composer"},
	"go.sum":              {kind: "lockfile", ecosystem: "go", packageManager: "go"},
	"npm-shrinkwrap.json": {kind: "lockfile", ecosystem: "node", packageManager: "npm"},
	"package-lock.json":   {kind: "lockfile", ecosystem: "node", packageManager: "npm"},
	"pnpm-lock.yaml":      {kind: "lockfile", ecosystem: "node", packageManager: "pnpm"},
	"poetry.lock":         {kind: "lockfile", ecosystem: "python", packageManager: "poetry"},
	"uv.lock":             {kind: "lockfile", ecosystem: "python", packageManager: "uv"},
	"yarn.lock":           {kind: "lockfile", ecosystem: "node", packageManager: "yarn"},
}

var packageManagerConfigFiles = map[string]inventoryMatch{
	".gemrc":            {kind: "package_manager_config_file", ecosystem: "ruby", packageManager: "gem"},
	".npmrc":            {kind: "package_manager_config_file", ecosystem: "node", packageManager: "npm"},
	".pnpmrc":           {kind: "package_manager_config_file", ecosystem: "node", packageManager: "pnpm"},
	".yarnrc":           {kind: "package_manager_config_file", ecosystem: "node", packageManager: "yarn"},
	".yarnrc.yml":       {kind: "package_manager_config_file", ecosystem: "node", packageManager: "yarn"},
	"gradle.properties": {kind: "package_manager_config_file", ecosystem: "java", packageManager: "gradle"},
	"pip.conf":          {kind: "package_manager_config_file", ecosystem: "python", packageManager: "pip"},
	"pip.ini":           {kind: "package_manager_config_file", ecosystem: "python", packageManager: "pip"},
	"poetry.toml":       {kind: "package_manager_config_file", ecosystem: "python", packageManager: "poetry"},
	"settings.xml":      {kind: "package_manager_config_file", ecosystem: "java", packageManager: "maven"},
}

func addInventoryItem(inventory *model.Inventory, item model.InventoryItem) {
	switch item.Kind {
	case "manifest":
		inventory.Manifests = append(inventory.Manifests, item)
	case "lockfile":
		inventory.Lockfiles = append(inventory.Lockfiles, item)
	case "package_manager_config_file":
		inventory.PackageManagerConfigFiles = append(inventory.PackageManagerConfigFiles, item)
	case "ci_workflow":
		inventory.CIWorkflows = append(inventory.CIWorkflows, item)
	case "dependency_bot":
		inventory.DependencyBots = append(inventory.DependencyBots, item)
	}
}

func populateInventorySummaries(inventory *model.Inventory) {
	ecosystems := map[string][]model.Location{}
	packageManagers := map[string][]model.Location{}
	for _, item := range inventoryFileItems(*inventory) {
		if item.Ecosystem != "" {
			ecosystems[item.Ecosystem] = append(ecosystems[item.Ecosystem], item.Locations...)
		}
		if item.PackageManager != "" {
			packageManagers[item.PackageManager] = append(packageManagers[item.PackageManager], item.Locations...)
		}
	}

	inventory.Ecosystems = summaryItems("ecosystem", ecosystems)
	inventory.PackageManagers = summaryItems("package_manager", packageManagers)
}

func inventoryFileItems(inventory model.Inventory) []model.InventoryItem {
	items := []model.InventoryItem{}
	items = append(items, inventory.Manifests...)
	items = append(items, inventory.Lockfiles...)
	items = append(items, inventory.PackageManagerConfigFiles...)
	items = append(items, inventory.CIWorkflows...)
	items = append(items, inventory.DependencyBots...)
	return items
}

func summaryItems(kind string, locationsByName map[string][]model.Location) []model.InventoryItem {
	names := make([]string, 0, len(locationsByName))
	for name := range locationsByName {
		names = append(names, name)
	}
	sort.Strings(names)

	items := make([]model.InventoryItem, 0, len(names))
	for _, name := range names {
		locations := locationsByName[name]
		sortLocations(locations)
		items = append(items, model.InventoryItem{
			ID:        inventoryItemID(kind, name),
			Name:      name,
			Kind:      kind,
			Locations: locations,
		})
	}
	return items
}

func sortLocations(locations []model.Location) {
	sort.Slice(locations, func(i, j int) bool {
		return locations[i].Path < locations[j].Path
	})
}

func sortWarnings(warnings []model.Warning) {
	sort.Slice(warnings, func(i, j int) bool {
		return warnings[i].Path < warnings[j].Path
	})
}

func inventoryItemID(kind string, value string) string {
	return fmt.Sprintf("%s:%s", kind, filepath.ToSlash(value))
}

func relativePath(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
