package gsimple

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/daaku/ghdeploy/ghook"
	"github.com/daaku/ghdeploy/grelease"
	"github.com/pkg/errors"
	"gopkg.in/mail.v2"
)

type Deployer struct {
	ServiceName      string
	InstallDir       string
	GithubToken      string
	GithubHookSecret []byte
	GithubAccount    string
	GithubRepo       string
	EmailClient      *mail.Dialer
	EmailFrom        string
	EmailTo          string
	deployLock       sync.Mutex
}

func (d *Deployer) deploy(ctx context.Context, releaseTag string) error {
	// install new release
	tmpDest, err := os.MkdirTemp(filepath.Dir(d.InstallDir), filepath.Base(d.InstallDir))
	if err != nil {
		return err
	}
	i := grelease.Install{
		Account:    d.GithubAccount,
		Repo:       d.GithubRepo,
		Token:      d.GithubToken,
		Dest:       tmpDest,
		ReleaseTag: releaseTag,
	}
	if err := i.Run(ctx); err != nil {
		return err
	}

	// remove old release
	if err := os.RemoveAll(d.InstallDir); err != nil {
		return err
	}

	// rename new to correct location
	if err := os.Rename(tmpDest, d.InstallDir); err != nil {
		return err
	}

	// retart service
	out, err := exec.Command("systemctl", "--user", "restart", d.ServiceName).
		CombinedOutput()
	if err != nil {
		return errors.Errorf("deploy: %s: %s", err, out)
	}
	return nil
}

func (d *Deployer) deployAndEmail(ctx context.Context, releaseTag string) {
	m := mail.NewMessage()
	m.SetAddressHeader("From", d.EmailFrom, fmt.Sprintf("Deploy %s", d.ServiceName))
	m.SetAddressHeader("To", d.EmailTo, "")

	if err := d.deploy(ctx, releaseTag); err != nil {
		m.SetHeader("Subject", fmt.Sprintf("Failed Deploy %s", releaseTag))
		m.AddAlternative("text/plain", fmt.Sprintf("%+v\n", err))
	} else {
		m.SetHeader("Subject", fmt.Sprintf("Deployed %s", releaseTag))
		currentRelease, err := os.ReadFile(filepath.Join(d.InstallDir, "release"))
		if err != nil {
			msg := fmt.Sprintf(
				"Deployed successfully, but error retriving current release tag: %+v", err)
			m.AddAlternative("text/plain", msg)
		} else {
			re := grelease.ReleaseEmail{
				Account:    d.GithubAccount,
				Repo:       d.GithubRepo,
				Token:      d.GithubToken,
				CurrentTag: string(currentRelease),
				NextTag:    releaseTag,
			}
			if msg, err := re.Generate(ctx); err != nil {
				msg := fmt.Sprintf(
					"Deployed successfully, but error generating release email: %+v", err)
				m.AddAlternative("text/plain", msg)
			} else {
				m.AddAlternative("text/html", msg)
			}
		}
	}
	if err := d.EmailClient.DialAndSend(m); err != nil {
		panic(err)
	}
}

func (d *Deployer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var event struct {
		Action  string `json:"action"`
		Release struct {
			TagName string `json:"tag_name"`
		} `json:"release"`
	}
	if err := ghook.Unmarshal(d.GithubHookSecret, r, &event); err != nil {
		status := http.StatusBadRequest
		if err == ghook.ErrEmptySecret || err == ghook.ErrHookMisconfigured {
			status = http.StatusInternalServerError
		}
		w.WriteHeader(status)
		fmt.Fprintln(w, err)
		return
	}
	if event.Action != "published" {
		fmt.Fprintf(w, "deploy: ignoring unexpected action: %v", event.Action)
		return
	}
	go d.deployAndEmail(r.Context(), event.Release.TagName)
	_, _ = io.WriteString(w, "deploy: successfully requested\n")
}
