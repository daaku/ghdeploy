// Package ghdeploy provides an opinionated deployment process using GitHub &
// systemd.
//
// It is meant for single instance web servers, and not useful if you're
// running a fleet of web servers.
//
// # Requirements
//
// • You are using a blue/green deployment strategy. This essentially means you
// will have some server in the front (haproxy, caddy, nginx etc) that will
// choose between the blue or the green instance, whichever is available.
//
// • You are using Github releases. It is expected the release upload a single
// file, which should be a tarball.
//
// • You are using systemd units to run your service. This should be a template
// unit, so the same unit is used for the blue and green instances.
//
// # Procedure
//
// • See example repo for how this should be setup.
//
// • Configure your Github webook to hit the endpoint you have configured.
//
// • Configure your Github webook and the deployer with the hook secret.
package ghdeploy

// TODO: switch to using sha256 signature
// TODO: on failure collect log from startup attempt and include in email
// TODO: include compare url in failure email
// TODO: include github action build url in email
// TODO: initial deployment
// TODO: tests

import (
	"archive/tar"
	"bytes"
	_ "embed"
	"encoding/json"
	perrors "errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-mail/mail"
	"github.com/pkg/errors"

	"github.com/daaku/ghdeploy/ghook"
)

type session struct {
	target struct {
		current, next int
	}
	tag struct {
		current, next string
	}
}

// Deployer handles deployment of new releases.
type Deployer struct {
	serviceName   string
	releasesDir   string
	directHandler bool
	healthCheck   struct {
		protocol string
		path     string
		timeout  time.Duration
	}
	targets struct {
		blue, green int
	}
	github struct {
		token      string
		hookSecret []byte
		account    string
		repo       string
	}
	email struct {
		client *mail.Dialer
		from   string
		to     string
	}

	deployLock sync.Mutex
}

// Option configures the Deployer.
type Option func(*Deployer)

// SystemdServiceName configures the base name of the unit. Defaults to
// GithubRepoName. It is expected this will be a template unit. See package
// documentation for more.
func SystemdServiceName(name string) Option {
	return func(d *Deployer) {
		d.serviceName = name
	}
}

// ReleasesDir is where the last two releases will be stored. The default is
// ~/.local/<service-name>.
func ReleasesDir(dir string) Option {
	return func(d *Deployer) {
		d.releasesDir = dir
	}
}

// HealthCheckPath configures the health check path. The default is /.
func HealthCheckPath(path string) Option {
	return func(d *Deployer) {
		d.healthCheck.path = path
	}
}

// HealthCheckProtocol must be one of tcp, http or https. The default is tcp,
// which simply checks for a successful connection. HTTP checks for a 200
// response on the configured path.
func HealthCheckProtocol(protocol string) Option {
	return func(d *Deployer) {
		d.healthCheck.protocol = protocol
	}
}

// HealthCheckTimeout specifies the duration we wait to check if a new service
// is healthy. The default is 30s.
func HealthCheckTimeout(timeout time.Duration) Option {
	return func(d *Deployer) {
		d.healthCheck.timeout = timeout
	}
}

// PortBlue is the first of two ports. The default is 8000.
func PortBlue(port int) Option {
	return func(d *Deployer) {
		d.targets.blue = port
	}
}

// PortGreen is the second of two ports. The default is 8001.
func PortGreen(port int) Option {
	return func(d *Deployer) {
		d.targets.green = port
	}
}

// GithubToken provides the Github API token.
func GithubToken(token string) Option {
	return func(d *Deployer) {
		d.github.token = token
	}
}

// GithubHookSecret provides the hook secret, if one is set. Leaving this blank
// will disable hook validation.
func GithubHookSecret(secret string) Option {
	return func(d *Deployer) {
		d.github.hookSecret = []byte(secret)
	}
}

// GithubAccount configures the Github account.
func GithubAccount(account string) Option {
	return func(d *Deployer) {
		d.github.account = account
	}
}

// GithubRepo configures the Github repo.
func GithubRepo(repo string) Option {
	return func(d *Deployer) {
		d.github.repo = repo
	}
}

// EmailClient configures the email client used to send success or failure
// emails on deployment.
func EmailClient(client *mail.Dialer) Option {
	return func(d *Deployer) {
		d.email.client = client
	}
}

// EmailFrom configures who the emails come from.
func EmailFrom(addr string) Option {
	return func(d *Deployer) {
		d.email.from = addr
	}
}

// EmailTo configures who the emails go to.
func EmailTo(addr string) Option {
	return func(d *Deployer) {
		d.email.to = addr
	}
}

// EnableDirectHandler enables a second handler under the path /direct/ that
// accepts a POST request with a `release_tag` parameter and triggers the deploy
// process. This is disabled by default, as it is an insecure endpoint. You may
// enable this at your discretion.
//
// This can be handy to quickly deploy a different release, and can be invoked
// as such:
//
//	curl http://myapp.com/webhook/github/direct/ -F release_tag=v42
func EnableDirectHandler(enable bool) Option {
	return func(d *Deployer) {
		d.directHandler = enable
	}
}

// New creates a new deployer. See package documenation for more.
func New(options ...Option) (*Deployer, error) {
	var d Deployer
	for _, o := range options {
		o(&d)
	}

	// required
	if d.github.token == "" {
		return nil, errors.New("deploy: GithubToken option must be provided")
	}
	if d.github.account == "" {
		return nil, errors.New("deploy: GithubAccount option must be provided")
	}
	if d.github.repo == "" {
		return nil, errors.New("deploy: GithubRepo option must be provided")
	}
	if d.email.client == nil {
		return nil, errors.New("deploy: EmailClient option must be provided")
	}
	if d.email.from == "" {
		return nil, errors.New("deploy: EmailFrom option must be provided")
	}
	if d.email.to == "" {
		return nil, errors.New("deploy: EmailTo option must be provided")
	}

	// defaults
	if d.serviceName == "" {
		d.serviceName = d.github.repo
	}
	if d.releasesDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		d.releasesDir = filepath.Join(home, ".local", d.serviceName)
	}
	if d.targets.blue == 0 {
		d.targets.blue = 8000
	}
	if d.targets.green == 0 {
		d.targets.green = 8001
	}
	if d.healthCheck.path == "" {
		d.healthCheck.path = "/"
	}
	if d.healthCheck.protocol == "" {
		d.healthCheck.protocol = "tcp"
	}
	if d.healthCheck.timeout == 0 {
		d.healthCheck.timeout = time.Second * 30
	}

	return &d, nil
}

func (d *Deployer) url(target int, path string) string {
	return fmt.Sprintf("%s://127.0.0.1:%d%s",
		d.healthCheck.protocol, target, path)
}

func (d *Deployer) path(target int) string {
	return filepath.Join(d.releasesDir, fmt.Sprint(target))
}

func (d *Deployer) service(target int) string {
	return fmt.Sprintf("%s@%d.service", d.serviceName, target)
}

func (d *Deployer) currentPort() (int, error) {
	out, err := exec.Command("systemctl", "--user", "list-units", d.serviceName+"@*", "--output", "json").
		CombinedOutput()
	if err != nil {
		return 0, errors.Errorf("deploy: %s: %s", err, out)
	}
	var units []struct {
		Unit string `json:"unit"`
	}
	if err := json.Unmarshal(out, &units); err != nil {
		return 0, errors.Errorf("deploy: error listing units: %s: %s", err, out)
	}
	if len(units) > 0 {
		_, portStr, _ := strings.Cut(strings.TrimSuffix(units[0].Unit, ".service"), "@")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return 0, errors.Errorf("deploy: unexpected template unit name: %s", units[0].Unit)
		}
		return port, nil
	}
	return 0, errors.Errorf("deploy: no active units for %s to determine current port", d.serviceName)
}

func (d *Deployer) releaseTag(target int) (string, error) {
	tag, err := os.ReadFile(filepath.Join(d.path(target), "release"))
	if err != nil {
		return "", errors.WithMessage(err, "deploy: reading release tag")
	}
	return string(bytes.TrimSpace(tag)), nil
}

func (d *Deployer) otherPort(target int) int {
	if d.targets.blue == target {
		return d.targets.green
	}
	if d.targets.green == target {
		return d.targets.blue
	}
	panic(fmt.Sprintf("deploy: not either blue or green: %d", target))
}

func (d *Deployer) systemctl(target int, op string) error {
	out, err := exec.Command("systemctl", "--user", op, d.service(target)).
		CombinedOutput()
	if err != nil {
		return errors.Errorf("deploy: %s: %s", err, out)
	}
	return nil
}

func (d *Deployer) isHealthy(target int, timeout time.Duration) error {
	end := time.Now().Add(timeout)
	for {
		var checkErr error
		if d.healthCheck.protocol == "tcp" {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", target), time.Millisecond*100)
			if err == nil {
				conn.Close()
				return nil
			}
			checkErr = err
		} else {
			res, err := http.Get(d.url(target, d.healthCheck.path))
			if res != nil {
				res.Body.Close()
			}
			if err == nil && res.StatusCode == http.StatusOK {
				return nil
			}
			checkErr = err
		}

		// ignore connect errors, bubble anything else
		if checkErr != nil {
			var scErr *os.SyscallError
			if !perrors.As(checkErr, &scErr) || scErr.Syscall != "connect" {
				return errors.Errorf(
					"deploy: unknown error for service on port %d: %s", target, checkErr)
			}
		}

		if time.Now().After(end) {
			return errors.Errorf("deploy: service on port %d is still not healthy", target)
		}

		time.Sleep(time.Millisecond * 50)
	}
}

func (d *Deployer) isHealthSnapshot(target int) error {
	return d.isHealthy(target, 0)
}

func (d *Deployer) isHealthWait(target int) error {
	return d.isHealthy(target, d.healthCheck.timeout)
}

func (d *Deployer) removeTarget(target int) error {
	if d.isHealthSnapshot(target) == nil {
		return errors.Errorf(
			"deploy: refusing to remove healthy service on port %d", target)
	}
	if err := os.RemoveAll(d.path(target)); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (d *Deployer) githubGet(url string, result interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", d.github.token))
	req.Header.Set("Accept", "application/vnd.github.v3.raw")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.WithStack(err)
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (d *Deployer) installTarget(target int, releaseTag string) error {
	var release struct {
		Assets []struct {
			URL string `json:"url"`
		} `json:"assets"`
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s",
		d.github.account, d.github.repo, releaseTag)
	retries := 3
	for {
		if err := d.githubGet(url, &release); err != nil {
			return err
		}
		if len(release.Assets) != 0 {
			break
		}
		if retries == 0 {
			return errors.Errorf("deploy: no releases found for tag: %s", releaseTag)
		}
		retries--
		time.Sleep(time.Second)
	}

	req, err := http.NewRequest("GET", release.Assets[0].URL, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", d.github.token))
	req.Header.Set("Accept", "application/octet-stream")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.WithStack(err)
	}
	defer res.Body.Close()

	dir := d.path(target)
	tarReader := tar.NewReader(res.Body)
	for {
		hd, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.WithStack(err)
		}

		fp := path.Join(dir, hd.Name)
		mode := hd.FileInfo().Mode()
		switch hd.Typeflag {
		default:
			return errors.Errorf(
				"deploy: unsupported tar entry of type %v for file %q",
				hd.Typeflag, hd.Name)
		case tar.TypeDir:
			if err := os.MkdirAll(fp, mode); err != nil {
				return errors.WithStack(err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(fp), mode); err != nil {
				return errors.WithStack(err)
			}
			file, err := os.Create(fp)
			if err != nil {
				return errors.WithStack(err)
			}
			if err := file.Chmod(mode); err != nil {
				return errors.WithStack(err)
			}
			if _, err := io.Copy(file, tarReader); err != nil {
				return errors.WithStack(err)
			}
			if err := file.Close(); err != nil {
				return errors.WithStack(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "release"), []byte(releaseTag), 0o655); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (d *Deployer) startTarget(target int) error {
	if d.isHealthSnapshot(target) == nil {
		return errors.Errorf(
			`deploy: refusing to start service on port %d which is `+
				`already healthy. this means we removed and installed over a `+
				`somehow healthy target.`, target)
	}

	if err := d.systemctl(target, "restart"); err != nil {
		return err
	}

	// now expect it to be eventually healthy
	if err := d.isHealthWait(target); err != nil {
		// kill it since it seems to be bad
		_ = d.systemctl(target, "stop")
		return errors.Errorf(
			`deploy: failed due to bad health check for service `+
				`on port %d: %s`, target, err)
	}

	// make sure this build is used on restarts, and other one is disabled
	if err := d.systemctl(target, "enable"); err != nil {
		return err
	}
	otherTarget := d.otherPort(target)
	if err := d.systemctl(otherTarget, "disable"); err != nil {
		return err
	}

	return nil
}

func (d *Deployer) sendShutdownSignal(target int) error {
	return d.systemctl(target, "stop")
}

func (d *Deployer) deploy(releaseTag string) (session, error) {
	d.deployLock.Lock()
	defer d.deployLock.Unlock()

	if releaseTag == "" {
		return session{}, errors.New("deploy: tried to deploy empty release tag")
	}
	s, err := d.session(releaseTag)
	if err != nil {
		return s, err
	}
	if err := d.removeTarget(s.target.next); err != nil {
		return s, err
	}
	if err := d.installTarget(s.target.next, s.tag.next); err != nil {
		return s, err
	}
	if err := d.startTarget(s.target.next); err != nil {
		return s, err
	}
	log.Printf("Started new release %s\n", releaseTag)
	return s, nil
}

type compareResponse struct {
	URL     string `json:"html_url"`
	Commits []struct {
		Commit struct {
			Message string `json:"message"`
		} `json:"commit"`
		URL string `json:"html_url"`
	} `json:"commits"`
}

//go:embed release_email.html
var releaseEmailTemplate string
var releaseEmail = template.Must(template.New("release_email").Parse(releaseEmailTemplate))

func (d *Deployer) releaseEmail(s session) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s...%s",
		d.github.account, d.github.repo, s.tag.current, s.tag.next)
	var result compareResponse
	if err := d.githubGet(url, &result); err != nil {
		return "", err
	}
	ctx := struct {
		CurrentReleaseTag string
		Compare           *compareResponse
	}{
		CurrentReleaseTag: s.tag.current,
		Compare:           &result,
	}
	var b strings.Builder
	if err := releaseEmail.Execute(&b, ctx); err != nil {
		return "", errors.WithMessage(err, "deploy: in rendering release email")
	}
	return b.String(), nil
}

func (d *Deployer) session(releaseTag string) (session, error) {
	var err error
	var s session
	s.tag.next = releaseTag
	if s.target.current, err = d.currentPort(); err != nil {
		return s, err
	}
	if s.tag.current, err = d.releaseTag(s.target.current); err != nil {
		return s, err
	}
	s.target.next = d.otherPort(s.target.current)
	return s, nil
}

func (d *Deployer) deployAndEmail(releaseTag string) {
	m := mail.NewMessage()
	m.SetAddressHeader("From", d.email.from, fmt.Sprintf("Deploy %s", d.serviceName))
	m.SetAddressHeader("To", d.email.to, "")

	s, err := d.deploy(releaseTag)
	if err != nil {
		m.SetHeader("Subject", fmt.Sprintf("Failed Deploy %s", releaseTag))
		m.AddAlternative("text/plain", fmt.Sprintf("%+v\n", err))
		if err := d.email.client.DialAndSend(m); err != nil {
			panic(err)
		}
		return
	}

	m.SetHeader("Subject", fmt.Sprintf("Deployed %s", releaseTag))

	if msg, err := d.releaseEmail(s); err != nil {
		msg = fmt.Sprintf(
			"Deployed successfully, but error generating release email: %+v", err)
		m.AddAlternative("text/plain", msg)
	} else {
		m.AddAlternative("text/html", msg)
	}
	if err := d.email.client.DialAndSend(m); err != nil {
		panic(err)
	}
	if err := d.sendShutdownSignal(s.target.current); err != nil {
		panic(err)
	}
}

var deployRequested = []byte("deploy: successfully requested\n")

func (d *Deployer) hook(w http.ResponseWriter, r *http.Request) {
	var event struct {
		Action  string `json:"action"`
		Release struct {
			TagName string `json:"tag_name"`
		} `json:"release"`
	}
	if err := ghook.Unmarshal(d.github.hookSecret, r, &event); err != nil {
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
	go d.deployAndEmail(event.Release.TagName)
	_, _ = w.Write(deployRequested)
}

func (d *Deployer) direct(w http.ResponseWriter, r *http.Request) {
	go d.deployAndEmail(r.FormValue("release_tag"))
	_, _ = w.Write(deployRequested)
}

func (d *Deployer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d.directHandler && strings.HasSuffix(r.URL.Path, "/direct/") {
		d.direct(w, r)
		return
	}
	d.hook(w, r)
}
