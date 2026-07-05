package mac

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidate_ValidSELinux(t *testing.T) {
	cfg := &Config{
		SELinux: &SELinuxConfig{
			Mode:       "enforcing",
			PolicyType: "targeted",
			Booleans:   map[string]bool{"httpd_can_network_connect": true},
			FileContexts: []FileContextSpec{
				{Path: "/srv/myapp(/.*)?", Context: "httpd_sys_content_t", FileType: "all"},
			},
			Ports: []PortSpec{
				{Port: "8080", Protocol: "tcp", Type: "http_port_t"},
			},
			Modules: []ModuleSpec{
				{Name: "mypolicy", Source: "mypolicy.pp", State: "present"},
			},
		},
	}

	result := Validate(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "valid", result.Status)
	assert.Empty(t, result.Errors)
}

func TestValidate_ValidAppArmor(t *testing.T) {
	cfg := &Config{
		AppArmor: &AppArmorConfig{
			Profiles: []ProfileSpec{
				{Name: "nginx", Path: "/usr/sbin/nginx", Mode: "enforce"},
				{Name: "mysql", Path: "/usr/sbin/mysqld", Mode: "complain"},
			},
			CustomProfilesDir: "/etc/apparmor.d/local",
			Tunables:          map[string]string{"@{HOME}": "/home/*"},
		},
	}

	result := Validate(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "valid", result.Status)
	assert.Empty(t, result.Errors)
	assert.Len(t, result.Changes, 2)
}

func TestValidate_EmptyConfig(t *testing.T) {
	cfg := &Config{}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Status)
	assert.Contains(t, result.Errors[0], "at least one of")
}

func TestValidate_SELinuxInvalidMode(t *testing.T) {
	cfg := &Config{
		SELinux: &SELinuxConfig{
			Mode: "invalid_mode",
		},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Status)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "invalid SELinux mode")
}

func TestValidate_AppArmorInvalidMode(t *testing.T) {
	cfg := &Config{
		AppArmor: &AppArmorConfig{
			Profiles: []ProfileSpec{
				{Name: "test", Path: "/usr/bin/test", Mode: "invalid_mode"},
			},
		},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Status)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "invalid mode")
}

func TestValidate_SELinuxMissingFileContextPath(t *testing.T) {
	cfg := &Config{
		SELinux: &SELinuxConfig{
			FileContexts: []FileContextSpec{
				{Path: "", Context: "httpd_sys_content_t"},
			},
		},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "path is required")
}

func TestValidate_SELinuxMissingFileContextContext(t *testing.T) {
	cfg := &Config{
		SELinux: &SELinuxConfig{
			FileContexts: []FileContextSpec{
				{Path: "/srv/myapp(/.*)?", Context: ""},
			},
		},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Contains(t, result.Errors[0], "context is required")
}

func TestValidate_SELinuxMissingPortFields(t *testing.T) {
	cfg := &Config{
		SELinux: &SELinuxConfig{
			Ports: []PortSpec{
				{Port: "", Type: ""},
			},
		},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Len(t, result.Errors, 2)
}

func TestValidate_SELinuxMissingModuleName(t *testing.T) {
	cfg := &Config{
		SELinux: &SELinuxConfig{
			Modules: []ModuleSpec{
				{Name: ""},
			},
		},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Contains(t, result.Errors[0], "name is required")
}

func TestValidate_AppArmorMissingProfileName(t *testing.T) {
	cfg := &Config{
		AppArmor: &AppArmorConfig{
			Profiles: []ProfileSpec{
				{Name: "", Path: "/usr/bin/test", Mode: "enforce"},
			},
		},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Contains(t, result.Errors[0], "name is required")
}

func TestValidate_AppArmorMissingProfilePath(t *testing.T) {
	cfg := &Config{
		AppArmor: &AppArmorConfig{
			Profiles: []ProfileSpec{
				{Name: "test", Path: "", Mode: "enforce"},
			},
		},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Contains(t, result.Errors[0], "path is required")
}

func TestApply_SELinux_SetMode(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()

	var calledName string
	var calledArgs []string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calledName = name
		calledArgs = arg
		return exec.Command("echo", "ok")
	}

	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendSELinux }

	cfg := &Config{
		SELinux: &SELinuxConfig{
			Mode: "permissive",
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "applied", result.Status)
	assert.Equal(t, "setenforce", calledName)
	assert.Equal(t, []string{"0"}, calledArgs)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "selinux_mode", result.Changes[0].Resource)
}

func TestApply_SELinux_SetBooleans(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()

	var calls []string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calls = append(calls, name)
		return exec.Command("echo", "ok")
	}

	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendSELinux }

	cfg := &Config{
		SELinux: &SELinuxConfig{
			Booleans: map[string]bool{"httpd_can_network_connect": true},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Contains(t, calls, "setsebool")
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "selinux_boolean", result.Changes[0].Resource)
}

func TestApply_SELinux_FileContexts(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()

	var calls []string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calls = append(calls, name)
		return exec.Command("echo", "ok")
	}

	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendSELinux }

	cfg := &Config{
		SELinux: &SELinuxConfig{
			FileContexts: []FileContextSpec{
				{Path: "/srv/myapp(/.*)?", Context: "httpd_sys_content_t"},
			},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Contains(t, calls, "semanage")
	assert.Contains(t, calls, "restorecon")
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "selinux_file_context", result.Changes[0].Resource)
}

func TestApply_SELinux_Ports(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()

	var calledName string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calledName = name
		return exec.Command("echo", "ok")
	}

	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendSELinux }

	cfg := &Config{
		SELinux: &SELinuxConfig{
			Ports: []PortSpec{
				{Port: "8080", Protocol: "tcp", Type: "http_port_t"},
			},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "semanage", calledName)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "selinux_port", result.Changes[0].Resource)
}

func TestApply_SELinux_Modules(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()

	var calledName string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calledName = name
		return exec.Command("echo", "ok")
	}

	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendSELinux }

	cfg := &Config{
		SELinux: &SELinuxConfig{
			Modules: []ModuleSpec{
				{Name: "mypolicy", Source: "mypolicy.pp", State: "present"},
			},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "semodule", calledName)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "selinux_module", result.Changes[0].Resource)
	assert.Equal(t, "present", result.Changes[0].Action)
}

func TestApply_SELinux_ModuleAbsent(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()

	var calledArgs []string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calledArgs = arg
		return exec.Command("echo", "ok")
	}

	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendSELinux }

	cfg := &Config{
		SELinux: &SELinuxConfig{
			Modules: []ModuleSpec{
				{Name: "mypolicy", State: "absent"},
			},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, []string{"-r", "mypolicy"}, calledArgs)
	assert.Equal(t, "absent", result.Changes[0].Action)
}

func TestApply_AppArmor_EnforceProfile(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()

	var calledName string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calledName = name
		return exec.Command("echo", "ok")
	}

	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendAppArmor }

	cfg := &Config{
		AppArmor: &AppArmorConfig{
			Profiles: []ProfileSpec{
				{Name: "nginx", Path: "/usr/sbin/nginx", Mode: "enforce"},
			},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "aa-enforce", calledName)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "enforce", result.Changes[0].Action)
	assert.Equal(t, "apparmor_profile", result.Changes[0].Resource)
}

func TestApply_AppArmor_ComplainProfile(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()

	var calledName string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calledName = name
		return exec.Command("echo", "ok")
	}

	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendAppArmor }

	cfg := &Config{
		AppArmor: &AppArmorConfig{
			Profiles: []ProfileSpec{
				{Name: "mysql", Path: "/usr/sbin/mysqld", Mode: "complain"},
			},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "aa-complain", calledName)
	assert.Equal(t, "complain", result.Changes[0].Action)
}

func TestApply_AppArmor_DisableProfile(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()

	var calledName string
	execCommand = func(name string, arg ...string) *exec.Cmd {
		calledName = name
		return exec.Command("echo", "ok")
	}

	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendAppArmor }

	cfg := &Config{
		AppArmor: &AppArmorConfig{
			Profiles: []ProfileSpec{
				{Name: "test", Path: "/usr/bin/test", Mode: "disable"},
			},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "aa-disable", calledName)
	assert.Equal(t, "disable", result.Changes[0].Action)
}

func TestApply_NoBackend(t *testing.T) {
	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendNone }

	cfg := &Config{
		SELinux: &SELinuxConfig{Mode: "enforcing"},
	}

	result := Apply(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "failed", result.Status)
	assert.Contains(t, result.Errors[0], "no MAC system detected")
}

func TestApply_MismatchedBackend_SELinuxActiveAppArmorConfig(t *testing.T) {
	origBackend := detectBackend
	defer func() { detectBackend = origBackend }()
	detectBackend = func() macBackend { return backendSELinux }

	cfg := &Config{
		AppArmor: &AppArmorConfig{
			Profiles: []ProfileSpec{
				{Name: "test", Path: "/usr/bin/test", Mode: "enforce"},
			},
		},
	}

	result := Apply(cfg)
	assert.False(t, result.Success)
	assert.Contains(t, result.Errors[0], "AppArmor config provided but SELinux is active")
}

func TestDetectMACBackend(t *testing.T) {
	// Just verify the function runs without panic
	backend := detectMACBackend()
	assert.True(t, backend == backendSELinux || backend == backendAppArmor || backend == backendNone)
}
