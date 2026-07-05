package mac

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Config represents MAC configuration input. Can contain SELinux, AppArmor, or both
// (though only one will be active on any given system).
type Config struct {
	SELinux  *SELinuxConfig  `json:"selinux,omitempty" yaml:"selinux,omitempty"`
	AppArmor *AppArmorConfig `json:"apparmor,omitempty" yaml:"apparmor,omitempty"`
}

// SELinuxConfig defines SELinux policy settings.
type SELinuxConfig struct {
	Mode         string            `json:"mode,omitempty" yaml:"mode,omitempty"`               // enforcing, permissive, disabled
	PolicyType   string            `json:"policy_type,omitempty" yaml:"policy_type,omitempty"` // targeted, mls, minimum
	Booleans     map[string]bool   `json:"booleans,omitempty" yaml:"booleans,omitempty"`
	FileContexts []FileContextSpec `json:"file_contexts,omitempty" yaml:"file_contexts,omitempty"`
	Ports        []PortSpec        `json:"ports,omitempty" yaml:"ports,omitempty"`
	Modules      []ModuleSpec      `json:"modules,omitempty" yaml:"modules,omitempty"`
}

// FileContextSpec defines an SELinux file context mapping.
type FileContextSpec struct {
	Path     string `json:"path" yaml:"path"`
	Context  string `json:"context" yaml:"context"`
	FileType string `json:"file_type,omitempty" yaml:"file_type,omitempty"` // all, file, dir, socket, symlink
}

// PortSpec defines an SELinux port labeling rule.
type PortSpec struct {
	Port     string `json:"port" yaml:"port"`
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"` // tcp, udp
	Type     string `json:"type" yaml:"type"`                            // SELinux port type
}

// ModuleSpec defines an SELinux policy module.
type ModuleSpec struct {
	Name   string `json:"name" yaml:"name"`
	Source string `json:"source,omitempty" yaml:"source,omitempty"`
	State  string `json:"state,omitempty" yaml:"state,omitempty"` // present, absent
}

// AppArmorConfig defines AppArmor profile settings.
type AppArmorConfig struct {
	Profiles          []ProfileSpec     `json:"profiles,omitempty" yaml:"profiles,omitempty"`
	CustomProfilesDir string            `json:"custom_profiles_dir,omitempty" yaml:"custom_profiles_dir,omitempty"`
	Tunables          map[string]string `json:"tunables,omitempty" yaml:"tunables,omitempty"`
}

// ProfileSpec defines an AppArmor profile configuration.
type ProfileSpec struct {
	Name  string   `json:"name" yaml:"name"`
	Path  string   `json:"path" yaml:"path"`
	Mode  string   `json:"mode" yaml:"mode"` // enforce, complain, disable
	Rules []string `json:"rules,omitempty" yaml:"rules,omitempty"`
}

// Result represents the outcome of an apply or validate operation.
type Result struct {
	Success bool           `json:"success"`
	Status  string         `json:"status"`
	Changes []ChangeDetail `json:"changes,omitempty"`
	Errors  []string       `json:"errors,omitempty"`
}

// ChangeDetail describes a single change made or planned.
type ChangeDetail struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Name     string `json:"name"`
	Detail   string `json:"detail,omitempty"`
}

type macBackend int

const (
	backendSELinux macBackend = iota
	backendAppArmor
	backendNone
)

var (
	execCommand   = exec.Command
	detectBackend = detectMACBackend
	osReadFile    = os.ReadFile
)

func detectMACBackend() macBackend {
	// Check for SELinux
	if _, err := os.Stat("/etc/selinux/config"); err == nil {
		return backendSELinux
	}
	if _, err := exec.LookPath("getenforce"); err == nil {
		return backendSELinux
	}
	// Check for AppArmor
	if _, err := os.Stat("/sys/module/apparmor"); err == nil {
		return backendAppArmor
	}
	if _, err := exec.LookPath("apparmor_status"); err == nil {
		return backendAppArmor
	}
	return backendNone
}

// Apply applies MAC configuration based on the detected backend.
func Apply(cfg *Config) *Result {
	result := &Result{Success: true, Status: "applied"}

	backend := detectBackend()

	if backend == backendNone {
		result.Success = false
		result.Status = "failed"
		result.Errors = append(result.Errors, "no MAC system detected (neither SELinux nor AppArmor)")
		return result
	}

	if backend == backendSELinux && cfg.SELinux != nil {
		applySELinux(cfg.SELinux, result)
	} else if backend == backendAppArmor && cfg.AppArmor != nil {
		applyAppArmor(cfg.AppArmor, result)
	} else {
		// Backend is active but no matching config section provided
		if backend == backendSELinux && cfg.AppArmor != nil {
			result.Errors = append(result.Errors, "AppArmor config provided but SELinux is active")
			result.Success = false
			result.Status = "failed"
		} else if backend == backendAppArmor && cfg.SELinux != nil {
			result.Errors = append(result.Errors, "SELinux config provided but AppArmor is active")
			result.Success = false
			result.Status = "failed"
		}
	}

	if !result.Success {
		result.Status = "failed"
	}

	return result
}

func applySELinux(cfg *SELinuxConfig, result *Result) {
	// Set mode
	if cfg.Mode != "" {
		if err := selinuxSetMode(cfg.Mode); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("set mode: %v", err))
			result.Success = false
		} else {
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   "set",
				Resource: "selinux_mode",
				Name:     cfg.Mode,
				Detail:   fmt.Sprintf("SELinux mode set to %s", cfg.Mode),
			})
		}
	}

	// Set booleans
	for name, value := range cfg.Booleans {
		if err := selinuxSetBoolean(name, value); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("boolean %s: %v", name, err))
			result.Success = false
		} else {
			val := "off"
			if value {
				val = "on"
			}
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   "set",
				Resource: "selinux_boolean",
				Name:     name,
				Detail:   fmt.Sprintf("set to %s", val),
			})
		}
	}

	// File contexts
	for _, fc := range cfg.FileContexts {
		if err := selinuxAddFileContext(fc); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("file context %s: %v", fc.Path, err))
			result.Success = false
		} else {
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   "added",
				Resource: "selinux_file_context",
				Name:     fc.Path,
				Detail:   fmt.Sprintf("context %s", fc.Context),
			})
		}
	}

	// Ports
	for _, p := range cfg.Ports {
		if err := selinuxAddPort(p); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("port %s: %v", p.Port, err))
			result.Success = false
		} else {
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   "added",
				Resource: "selinux_port",
				Name:     p.Port,
				Detail:   fmt.Sprintf("type %s protocol %s", p.Type, p.Protocol),
			})
		}
	}

	// Modules
	for _, m := range cfg.Modules {
		if err := selinuxManageModule(m); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("module %s: %v", m.Name, err))
			result.Success = false
		} else {
			state := "present"
			if m.State == "absent" {
				state = "absent"
			}
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   state,
				Resource: "selinux_module",
				Name:     m.Name,
			})
		}
	}
}

func selinuxSetMode(mode string) error {
	arg := "1" // enforcing
	if mode == "permissive" {
		arg = "0"
	}
	cmd := execCommand("setenforce", arg)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("setenforce failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func selinuxSetBoolean(name string, value bool) error {
	val := "off"
	if value {
		val = "on"
	}
	cmd := execCommand("setsebool", "-P", name, val)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("setsebool failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func selinuxAddFileContext(fc FileContextSpec) error {
	args := []string{"fcontext", "-a", "-t", fc.Context}
	if fc.FileType != "" {
		args = append(args, "-f", fc.FileType)
	}
	args = append(args, fc.Path)
	cmd := execCommand("semanage", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("semanage fcontext failed: %s: %w", strings.TrimSpace(string(out)), err)
	}

	restoreCmd := execCommand("restorecon", "-Rv", fc.Path)
	if out, err := restoreCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restorecon failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func selinuxAddPort(p PortSpec) error {
	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}
	cmd := execCommand("semanage", "port", "-a", "-t", p.Type, "-p", proto, p.Port)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("semanage port failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func selinuxManageModule(m ModuleSpec) error {
	if m.State == "absent" {
		cmd := execCommand("semodule", "-r", m.Name)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("semodule remove failed: %s: %w", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	// present (default)
	source := m.Source
	if source == "" {
		source = m.Name + ".pp"
	}
	cmd := execCommand("semodule", "-i", source)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("semodule install failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func applyAppArmor(cfg *AppArmorConfig, result *Result) {
	for _, p := range cfg.Profiles {
		if err := apparmorSetProfile(p); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("profile %s: %v", p.Name, err))
			result.Success = false
		} else {
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   p.Mode,
				Resource: "apparmor_profile",
				Name:     p.Name,
				Detail:   fmt.Sprintf("path %s", p.Path),
			})
		}
	}
}

func apparmorSetProfile(p ProfileSpec) error {
	var cmd *exec.Cmd
	switch p.Mode {
	case "enforce":
		cmd = execCommand("aa-enforce", p.Path)
	case "complain":
		cmd = execCommand("aa-complain", p.Path)
	case "disable":
		cmd = execCommand("aa-disable", p.Path)
	default:
		return fmt.Errorf("unknown mode: %s", p.Mode)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %s: %w", p.Mode, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Validate checks MAC configuration without making changes.
func Validate(cfg *Config) *Result {
	result := &Result{Success: true, Status: "valid"}

	if cfg.SELinux == nil && cfg.AppArmor == nil {
		result.Success = false
		result.Status = "invalid"
		result.Errors = append(result.Errors, "config must contain at least one of: selinux, apparmor")
		return result
	}

	if cfg.SELinux != nil {
		validateSELinux(cfg.SELinux, result)
	}

	if cfg.AppArmor != nil {
		validateAppArmor(cfg.AppArmor, result)
	}

	if !result.Success {
		result.Status = "invalid"
	}

	return result
}

func validateSELinux(cfg *SELinuxConfig, result *Result) {
	// Validate mode
	if cfg.Mode != "" {
		validModes := map[string]bool{"enforcing": true, "permissive": true, "disabled": true}
		if !validModes[cfg.Mode] {
			result.Errors = append(result.Errors, fmt.Sprintf("invalid SELinux mode: %q (must be enforcing, permissive, or disabled)", cfg.Mode))
			result.Success = false
		} else {
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   "set",
				Resource: "selinux_mode",
				Name:     cfg.Mode,
			})
		}
	}

	// Validate policy type
	if cfg.PolicyType != "" {
		validTypes := map[string]bool{"targeted": true, "mls": true, "minimum": true}
		if !validTypes[cfg.PolicyType] {
			result.Errors = append(result.Errors, fmt.Sprintf("invalid SELinux policy type: %q", cfg.PolicyType))
			result.Success = false
		}
	}

	// Validate booleans (just report them)
	for name := range cfg.Booleans {
		result.Changes = append(result.Changes, ChangeDetail{
			Action:   "set",
			Resource: "selinux_boolean",
			Name:     name,
		})
	}

	// Validate file contexts
	for i, fc := range cfg.FileContexts {
		if fc.Path == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("file_contexts[%d]: path is required", i))
			result.Success = false
		}
		if fc.Context == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("file_contexts[%d]: context is required", i))
			result.Success = false
		}
		if fc.FileType != "" {
			validTypes := map[string]bool{"all": true, "file": true, "dir": true, "socket": true, "symlink": true}
			if !validTypes[fc.FileType] {
				result.Errors = append(result.Errors, fmt.Sprintf("file_contexts[%d]: invalid file_type %q", i, fc.FileType))
				result.Success = false
			}
		}
	}

	// Validate ports
	for i, p := range cfg.Ports {
		if p.Port == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("ports[%d]: port is required", i))
			result.Success = false
		}
		if p.Type == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("ports[%d]: type is required", i))
			result.Success = false
		}
		if p.Protocol != "" {
			validProtos := map[string]bool{"tcp": true, "udp": true}
			if !validProtos[p.Protocol] {
				result.Errors = append(result.Errors, fmt.Sprintf("ports[%d]: invalid protocol %q", i, p.Protocol))
				result.Success = false
			}
		}
	}

	// Validate modules
	for i, m := range cfg.Modules {
		if m.Name == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("modules[%d]: name is required", i))
			result.Success = false
		}
		if m.State != "" {
			validStates := map[string]bool{"present": true, "absent": true}
			if !validStates[m.State] {
				result.Errors = append(result.Errors, fmt.Sprintf("modules[%d]: invalid state %q", i, m.State))
				result.Success = false
			}
		}
	}
}

func validateAppArmor(cfg *AppArmorConfig, result *Result) {
	for i, p := range cfg.Profiles {
		if p.Name == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("profiles[%d]: name is required", i))
			result.Success = false
		}
		if p.Path == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("profiles[%d]: path is required", i))
			result.Success = false
		}
		if p.Mode == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("profiles[%d]: mode is required", i))
			result.Success = false
		} else {
			validModes := map[string]bool{"enforce": true, "complain": true, "disable": true}
			if !validModes[p.Mode] {
				result.Errors = append(result.Errors, fmt.Sprintf("profiles[%d]: invalid mode %q (must be enforce, complain, or disable)", i, p.Mode))
				result.Success = false
			} else {
				result.Changes = append(result.Changes, ChangeDetail{
					Action:   p.Mode,
					Resource: "apparmor_profile",
					Name:     p.Name,
				})
			}
		}
	}
}
