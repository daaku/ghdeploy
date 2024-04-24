package grelease

import (
	"archive/tar"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/pkg/errors"
)

func setToken(token string, r *http.Request) {
	r.Header.Set("Authorization", fmt.Sprintf("Token %s", token))
}

func get(
	ctx context.Context,
	transport http.RoundTripper,
	token string,
	url string,
	result interface{},
) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	setToken(token, req)
	req.Header.Set("Accept", "application/vnd.github.v3.raw")

	if transport == nil {
		transport = http.DefaultTransport
	}
	res, err := transport.RoundTrip(req)
	if err != nil {
		return errors.WithStack(err)
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type Install struct {
	Transport  http.RoundTripper
	Account    string
	Repo       string
	Token      string
	ReleaseTag string
	Dest       string
}

func (i Install) Run(ctx context.Context) error {
	var release struct {
		Assets []struct {
			URL string `json:"url"`
		} `json:"assets"`
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s",
		i.Account, i.Repo, i.ReleaseTag)
	retries := 3
	for {
		if err := get(ctx, i.Transport, i.Token, url, &release); err != nil {
			return err
		}
		if len(release.Assets) != 0 {
			break
		}
		if retries == 0 {
			return errors.Errorf("deploy: no releases found for tag: %s", i.ReleaseTag)
		}
		retries--
		time.Sleep(time.Second)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", release.Assets[0].URL, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	setToken(i.Token, req)
	req.Header.Set("Accept", "application/octet-stream")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.WithStack(err)
	}
	defer res.Body.Close()

	tarReader := tar.NewReader(res.Body)
	for {
		hd, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.WithStack(err)
		}

		fp := path.Join(i.Dest, hd.Name)
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
	if err := os.WriteFile(filepath.Join(i.Dest, "release"), []byte(i.ReleaseTag), 0o655); err != nil {
		return errors.WithStack(err)
	}
	return nil
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

type ReleaseEmail struct {
	Transport           http.RoundTripper
	Account             string
	Repo                string
	Token               string
	CurrentTag, NextTag string
}

func (r ReleaseEmail) Generate(ctx context.Context) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s...%s",
		r.Account, r.Repo, r.CurrentTag, r.NextTag)
	var result compareResponse
	if err := get(ctx, r.Transport, r.Token, url, &result); err != nil {
		return "", err
	}
	tc := struct {
		CurrentReleaseTag string
		Compare           *compareResponse
	}{
		CurrentReleaseTag: r.CurrentTag,
		Compare:           &result,
	}
	var b strings.Builder
	if err := releaseEmail.Execute(&b, tc); err != nil {
		return "", errors.WithMessage(err, "deploy: in rendering release email")
	}
	return b.String(), nil
}
