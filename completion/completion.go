package completion

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

//go:embed goshs.bash
var bashScript []byte

//go:embed goshs.fish
var fishScript []byte

//go:embed _goshs
var zshScript []byte

// Install installs shell completion for the given shell.
// Pass an empty string to auto-detect from $SHELL.
func Install(shell string) error {
	if shell == "" {
		shell = detectShell()
		if shell == "" {
			return fmt.Errorf("could not detect shell; pass bash, fish, or zsh explicitly")
		}
		fmt.Printf("Detected shell: %s\n", shell)
	}

	switch shell {
	case "bash":
		return installBash()
	case "fish":
		return installFish()
	case "zsh":
		return installZsh()
	default:
		return fmt.Errorf("unsupported shell %q — supported: bash, fish, zsh", shell)
	}
}

func detectShell() string {
	s := os.Getenv("SHELL")
	if s == "" {
		return ""
	}
	return filepath.Base(s)
}

func isRoot() bool {
	return os.Getuid() == 0
}

// homebrewPrefix returns the brew --prefix output, or "" if Homebrew is absent.
func homebrewPrefix() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	out, err := exec.Command("brew", "--prefix").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func writeWithSudo(path string, data []byte) error {
	tmp, err := os.CreateTemp("", "goshs-completion-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	tmp.Close()

	dir := filepath.Dir(path)
	if err := runSudo("mkdir", "-p", dir); err != nil {
		return fmt.Errorf("sudo mkdir -p %s: %w", dir, err)
	}
	if err := runSudo("cp", tmp.Name(), path); err != nil {
		return fmt.Errorf("sudo cp to %s: %w", path, err)
	}
	return runSudo("chmod", "644", path)
}

func runSudo(args ...string) error {
	cmd := exec.Command("sudo", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// tryInstall writes to path without sudo first, falling back to sudo on permission errors.
func tryInstall(path string, data []byte) error {
	if err := writeFile(path, data); err == nil {
		return nil
	}
	fmt.Printf("No write permission to %s, trying sudo...\n", filepath.Dir(path))
	return writeWithSudo(path, data)
}

func installBash() error {
	var path string

	if prefix := homebrewPrefix(); prefix != "" {
		path = filepath.Join(prefix, "etc", "bash_completion.d", "goshs")
		fmt.Printf("Homebrew detected — installing to %s\n", path)
	} else if isRoot() {
		path = "/etc/bash_completion.d/goshs"
	} else {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".local", "share", "bash-completion", "completions", "goshs")
	}

	if err := tryInstall(path, bashScript); err != nil {
		return err
	}

	fmt.Printf("\n✓ Bash completion installed to %s\n\n", path)
	fmt.Printf("To activate it in your current session, run:\n")
	fmt.Printf("  source %s\n\n", path)
	fmt.Println("New shell sessions will load it automatically (requires the bash-completion package).")
	return nil
}

func installFish() error {
	var path string

	if prefix := homebrewPrefix(); prefix != "" {
		path = filepath.Join(prefix, "share", "fish", "vendor_completions.d", "goshs.fish")
		fmt.Printf("Homebrew detected — installing to %s\n", path)
	} else if isRoot() {
		path = "/usr/share/fish/vendor_completions.d/goshs.fish"
	} else {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".config", "fish", "completions", "goshs.fish")
	}

	if err := tryInstall(path, fishScript); err != nil {
		return err
	}

	fmt.Printf("\n✓ Fish completion installed to %s\n\n", path)
	fmt.Printf("To activate it in your current session, run:\n")
	fmt.Printf("  exec fish\n\n")
	fmt.Println("New fish sessions will load it automatically.")
	return nil
}

func installZsh() error {
	var path string
	var userInstall bool

	if prefix := homebrewPrefix(); prefix != "" {
		path = filepath.Join(prefix, "share", "zsh", "site-functions", "_goshs")
		fmt.Printf("Homebrew detected — installing to %s\n", path)
	} else if isRoot() {
		path = "/usr/local/share/zsh/site-functions/_goshs"
	} else {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".local", "share", "zsh", "site-functions", "_goshs")
		userInstall = true
	}

	if err := tryInstall(path, zshScript); err != nil {
		return err
	}

	fmt.Printf("\n✓ Zsh completion installed to %s\n\n", path)

	if userInstall {
		dir := filepath.Dir(path)
		fmt.Printf("To activate it, add the following to your ~/.zshrc (if not already present):\n")
		fmt.Printf("  fpath=(%s $fpath)\n", dir)
		fmt.Printf("  autoload -U compinit && compinit\n\n")
		fmt.Println("Then restart your shell or run: exec zsh")
	} else {
		fmt.Printf("To activate it in your current session, run:\n")
		fmt.Printf("  autoload -U compinit && compinit\n\n")
		fmt.Println("New shell sessions will load it automatically.")
	}
	return nil
}
