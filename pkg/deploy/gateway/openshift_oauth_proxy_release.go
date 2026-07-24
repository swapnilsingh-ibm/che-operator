//
// Copyright (c) 2019-2026 Red Hat, Inc.
// This program and the accompanying materials are made
// available under the terms of the Eclipse Public License 2.0
// which is available at https://www.eclipse.org/legal/epl-2.0/
//
// SPDX-License-Identifier: EPL-2.0
//
// Contributors:
//   Red Hat, Inc. - initial API and implementation
//

package gateway

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/eclipse-che/che-operator/pkg/common/chetypes"
	"github.com/eclipse-che/che-operator/pkg/deploy"
	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const (
	openShiftOAuthProxyImageName = "oauth-proxy"
	openShiftPullSecretNamespace = "openshift-config"
	openShiftPullSecretName      = "pull-secret"
	releaseImageReferencesPath   = "release-manifests/image-references"

	registryHTTPTimeout         = 30 * time.Second
	registryHTTPOverallTimeout  = 2 * time.Minute
	registryLayerSizeLimitBytes = 64 << 20 // 64MiB
)

func findOpenShiftOAuthProxyImageFromRelease(ctx *chetypes.DeployContext) string {
	if ctx == nil || ctx.ClusterAPI.NonCachingClientWrapper == nil {
		return ""
	}

	clusterVersion := &configv1.ClusterVersion{}
	exists, err := ctx.ClusterAPI.NonCachingClientWrapper.GetIgnoreNotFound(
		context.TODO(),
		types.NamespacedName{Name: "version"},
		clusterVersion,
	)
	if err != nil {
		openShiftOAuthProxyImageLog.Info("failed to read ClusterVersion while resolving oauth-proxy image", "error", err.Error())
		return ""
	}
	if !exists {
		openShiftOAuthProxyImageLog.V(1).Info("ClusterVersion version not found")
		return ""
	}

	releaseImage := strings.TrimSpace(clusterVersion.Status.Desired.Image)
	if releaseImage == "" {
		openShiftOAuthProxyImageLog.Info("ClusterVersion status.desired.image is empty")
		return ""
	}

	pullSecret := &corev1.Secret{}
	exists, err = ctx.ClusterAPI.NonCachingClientWrapper.GetIgnoreNotFound(
		context.TODO(),
		types.NamespacedName{Name: openShiftPullSecretName, Namespace: openShiftPullSecretNamespace},
		pullSecret,
	)
	if err != nil {
		openShiftOAuthProxyImageLog.Info("failed to read OpenShift pull-secret while resolving oauth-proxy image", "error", err.Error())
		return ""
	}
	if !exists {
		openShiftOAuthProxyImageLog.Info("OpenShift pull-secret not found; cannot extract oauth-proxy from release image")
		return ""
	}

	dockerConfig := pullSecret.Data[".dockerconfigjson"]
	if len(dockerConfig) == 0 {
		dockerConfig = pullSecret.Data[".dockercfg"]
	}
	if len(dockerConfig) == 0 {
		openShiftOAuthProxyImageLog.Info("OpenShift pull-secret has no docker config data")
		return ""
	}

	client := newRegistryHTTPClient(ctx)
	image, err := extractOAuthProxyImageFromRelease(client, releaseImage, dockerConfig)
	if err != nil {
		openShiftOAuthProxyImageLog.Info(
			"failed to extract oauth-proxy image from OpenShift release payload",
			"releaseImage", releaseImage,
			"error", err.Error(),
		)
		return ""
	}

	openShiftOAuthProxyImageLog.Info(
		"resolved OpenShift oauth-proxy image from cluster release payload",
		"releaseImage", releaseImage,
		"image", image,
	)
	return image
}

func newRegistryHTTPClient(ctx *chetypes.DeployContext) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   registryHTTPTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   registryHTTPTimeout,
		ResponseHeaderTimeout: registryHTTPTimeout,
		ExpectContinueTimeout: 5 * time.Second,
	}
	if ctx != nil && ctx.Proxy != nil {
		deploy.ConfigureProxy(ctx, transport)
	}
	return &http.Client{
		Timeout:   registryHTTPOverallTimeout,
		Transport: transport,
	}
}

func extractOAuthProxyImageFromRelease(client *http.Client, releaseImage string, dockerConfig []byte) (string, error) {
	ref, err := parseImageReference(releaseImage)
	if err != nil {
		return "", err
	}

	token, err := registryAuthToken(client, ref, dockerConfig)
	if err != nil {
		return "", fmt.Errorf("registry auth: %w", err)
	}

	manifestBytes, mediaType, err := fetchManifest(client, ref, token)
	if err != nil {
		return "", fmt.Errorf("fetch manifest: %w", err)
	}

	if strings.Contains(mediaType, "manifest.list") || strings.Contains(mediaType, "image.index") {
		childDigest, err := chooseManifestDigest(manifestBytes)
		if err != nil {
			return "", err
		}
		ref.digest = childDigest
		ref.tag = ""
		manifestBytes, mediaType, err = fetchManifest(client, ref, token)
		if err != nil {
			return "", fmt.Errorf("fetch platform manifest: %w", err)
		}
	}

	layers, err := manifestLayers(manifestBytes, mediaType)
	if err != nil {
		return "", err
	}

	for _, layerDigest := range layers {
		refs, err := readImageReferencesFromLayer(client, ref, token, layerDigest)
		if err != nil {
			openShiftOAuthProxyImageLog.V(1).Info("skipping release layer", "layer", layerDigest, "error", err.Error())
			continue
		}
		if refs == nil {
			continue
		}
		return oauthProxyFromImageReferences(refs)
	}

	return "", fmt.Errorf("release image %q does not contain %s", releaseImage, releaseImageReferencesPath)
}

type imageRef struct {
	registry   string
	repository string
	digest     string
	tag        string
}

func parseImageReference(image string) (*imageRef, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return nil, fmt.Errorf("empty image reference")
	}

	var digest, tag, path string
	switch {
	case strings.Contains(image, "@"):
		parts := strings.SplitN(image, "@", 2)
		path, digest = parts[0], parts[1]
	default:
		lastSlash := strings.LastIndex(image, "/")
		lastColon := strings.LastIndex(image, ":")
		if lastColon > lastSlash {
			path, tag = image[:lastColon], image[lastColon+1:]
		} else {
			path = image
		}
	}

	slash := strings.Index(path, "/")
	if slash < 0 {
		return nil, fmt.Errorf("invalid image reference %q", image)
	}
	registry, repository := path[:slash], path[slash+1:]
	if registry == "" || repository == "" {
		return nil, fmt.Errorf("invalid image reference %q", image)
	}
	if digest == "" && tag == "" {
		tag = "latest"
	}
	return &imageRef{registry: registry, repository: repository, digest: digest, tag: tag}, nil
}

var (
	// registryScheme is https in production. Tests may set it to http for httptest.
	registryScheme = "https"
)

func (r *imageRef) manifestURL() string {
	ref := r.tag
	if r.digest != "" {
		ref = r.digest
	}
	return fmt.Sprintf("%s://%s/v2/%s/manifests/%s", registryScheme, r.registry, r.repository, ref)
}

func (r *imageRef) blobURL(digest string) string {
	return fmt.Sprintf("%s://%s/v2/%s/blobs/%s", registryScheme, r.registry, r.repository, digest)
}

type dockerConfigJSON struct {
	Auths map[string]dockerAuthEntry `json:"auths"`
}

type dockerAuthEntry struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func registryAuthToken(client *http.Client, ref *imageRef, dockerConfig []byte) (string, error) {
	user, pass, err := credentialsForRegistry(dockerConfig, ref.registry)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodGet, ref.manifestURL(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", strings.Join(manifestAcceptHeaders(), ", "))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "", nil
	}

	authHeader := resp.Header.Get("Www-Authenticate")
	if authHeader == "" && user != "" {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), nil
	}

	challenge, err := parseBearerChallenge(authHeader)
	if err != nil {
		if user != "" {
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), nil
		}
		return "", err
	}

	tokenURL := challenge["realm"]
	if tokenURL == "" {
		return "", fmt.Errorf("bearer challenge missing realm")
	}
	scope := challenge["scope"]
	if scope == "" {
		scope = fmt.Sprintf("repository:%s:pull", ref.repository)
	}

	tokenReq, err := http.NewRequest(http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	q := tokenReq.URL.Query()
	if service := challenge["service"]; service != "" {
		q.Set("service", service)
	}
	q.Set("scope", scope)
	tokenReq.URL.RawQuery = q.Encode()
	if user != "" {
		tokenReq.SetBasicAuth(user, pass)
	}

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return "", err
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(tokenResp.Body, 2048))
		return "", fmt.Errorf("token endpoint returned %s: %s", tokenResp.Status, string(body))
	}

	var tokenPayload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenPayload); err != nil {
		return "", err
	}
	token := tokenPayload.Token
	if token == "" {
		token = tokenPayload.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("token endpoint returned empty token")
	}
	return "Bearer " + token, nil
}

func credentialsForRegistry(dockerConfig []byte, registry string) (string, string, error) {
	var cfg dockerConfigJSON
	if err := json.Unmarshal(dockerConfig, &cfg); err != nil {
		var legacy map[string]dockerAuthEntry
		if err2 := json.Unmarshal(dockerConfig, &legacy); err2 != nil {
			return "", "", fmt.Errorf("parse pull secret: %w", err)
		}
		cfg.Auths = legacy
	}

	candidates := []string{
		registry,
		"https://" + registry,
		"https://" + registry + "/v1/",
		"http://" + registry,
	}
	for _, key := range candidates {
		entry, ok := cfg.Auths[key]
		if !ok {
			continue
		}
		if entry.Username != "" || entry.Password != "" {
			return entry.Username, entry.Password, nil
		}
		if entry.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				return "", "", err
			}
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) != 2 {
				return "", "", fmt.Errorf("invalid auth for registry %s", key)
			}
			return parts[0], parts[1], nil
		}
	}
	return "", "", nil
}

func parseBearerChallenge(header string) (map[string]string, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, fmt.Errorf("empty www-authenticate header")
	}
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return nil, fmt.Errorf("unsupported www-authenticate: %s", header)
	}
	params := map[string]string{}
	for _, part := range strings.Split(header[len("bearer "):], ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		params[strings.ToLower(kv[0])] = strings.Trim(kv[1], `"`)
	}
	return params, nil
}

func manifestAcceptHeaders() []string {
	return []string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}
}

func fetchManifest(client *http.Client, ref *imageRef, authHeader string) ([]byte, string, error) {
	req, err := http.NewRequest(http.MethodGet, ref.manifestURL(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", strings.Join(manifestAcceptHeaders(), ", "))
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s: %s", resp.Status, string(body))
	}
	mediaType := resp.Header.Get("Content-Type")
	if mediaType == "" {
		mediaType = "application/vnd.docker.distribution.manifest.v2+json"
	}
	return body, mediaType, nil
}

func chooseManifestDigest(indexBytes []byte) (string, error) {
	var index struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return "", err
	}

	arch := runtime.GOARCH
	for _, m := range index.Manifests {
		if m.Platform.OS == "linux" && m.Platform.Architecture == arch && m.Digest != "" {
			return m.Digest, nil
		}
	}
	for _, m := range index.Manifests {
		if m.Platform.OS == "linux" && m.Digest != "" {
			return m.Digest, nil
		}
	}
	if len(index.Manifests) > 0 && index.Manifests[0].Digest != "" {
		return index.Manifests[0].Digest, nil
	}
	return "", fmt.Errorf("manifest list has no usable child manifests")
}

func manifestLayers(manifestBytes []byte, mediaType string) ([]string, error) {
	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest (%s): %w", mediaType, err)
	}
	var digests []string
	for _, layer := range manifest.Layers {
		if layer.Digest != "" {
			digests = append(digests, layer.Digest)
		}
	}
	if len(digests) == 0 {
		return nil, fmt.Errorf("manifest has no layers")
	}
	return digests, nil
}

func readImageReferencesFromLayer(client *http.Client, ref *imageRef, authHeader, layerDigest string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, ref.blobURL(layerDigest), nil)
	if err != nil {
		return nil, err
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("blob %s: %s %s", layerDigest, resp.Status, string(body))
	}

	layerBytes, err := io.ReadAll(io.LimitReader(resp.Body, registryLayerSizeLimitBytes))
	if err != nil {
		return nil, err
	}

	var tarReader *tar.Reader
	if gz, err := gzip.NewReader(bytes.NewReader(layerBytes)); err == nil {
		defer gz.Close()
		tarReader = tar.NewReader(gz)
	} else {
		tarReader = tar.NewReader(bytes.NewReader(layerBytes))
	}

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name == releaseImageReferencesPath || strings.HasSuffix(name, "/"+releaseImageReferencesPath) || name == "image-references" {
			return io.ReadAll(io.LimitReader(tarReader, 16<<20))
		}
	}
}

func oauthProxyFromImageReferences(imageReferences []byte) (string, error) {
	obj := map[string]interface{}{}
	if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(imageReferences), 4096).Decode(&obj); err != nil {
		return "", fmt.Errorf("parse image-references: %w", err)
	}
	u := &unstructured.Unstructured{Object: obj}
	tags, found, err := unstructured.NestedSlice(u.Object, "spec", "tags")
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("image-references has no spec.tags")
	}
	for _, raw := range tags {
		tag, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name, _, _ := unstructured.NestedString(tag, "name")
		if name != openShiftOAuthProxyImageName {
			continue
		}
		image, _, _ := unstructured.NestedString(tag, "from", "name")
		if strings.TrimSpace(image) == "" {
			return "", fmt.Errorf("oauth-proxy tag has empty from.name")
		}
		return image, nil
	}
	return "", fmt.Errorf("oauth-proxy tag not found in image-references")
}
