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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	chev2 "github.com/eclipse-che/che-operator/api/v2"
	"github.com/eclipse-che/che-operator/pkg/common/constants"
	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	defaults "github.com/eclipse-che/che-operator/pkg/common/operator-defaults"
	"github.com/eclipse-che/che-operator/pkg/common/test"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetOpenShiftOAuthProxyImageFallsBackToRelatedImage(t *testing.T) {
	resetOpenShiftOAuthProxyImageCache()
	infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)

	ctx := test.NewCtxBuilder().Build()
	expected := defaults.GetGatewayOpenShiftAuthenticationSidecarImage(ctx.CheCluster)

	assert.Equal(t, expected, getOpenShiftOAuthProxyImage(ctx))
	assert.Equal(t, expected, getOauthProxyContainerSpec(ctx).Image)
}

func TestCheClusterOauthProxyImageOverrideStillWins(t *testing.T) {
	resetOpenShiftOAuthProxyImageCache()
	infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)

	customImage := "example.com/custom-oauth-proxy:test"
	checluster := &chev2.CheCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eclipse-che",
			Namespace: "eclipse-che",
		},
		Spec: chev2.CheClusterSpec{
			Networking: chev2.CheClusterSpecNetworking{
				Auth: chev2.Auth{
					Gateway: chev2.Gateway{
						Deployment: &chev2.Deployment{
							Containers: []chev2.Container{
								{
									Name:  constants.GatewayAuthenticationContainerName,
									Image: customImage,
								},
							},
						},
					},
				},
			},
		},
	}

	ctx := test.NewCtxBuilder().WithCheCluster(checluster).Build()
	deployment, err := getGatewayDeploymentSpec(ctx)
	assert.NoError(t, err)

	var oauthProxyImage string
	for _, c := range deployment.Spec.Template.Spec.Containers {
		if c.Name == constants.GatewayAuthenticationContainerName {
			oauthProxyImage = c.Image
			break
		}
	}
	assert.Equal(t, customImage, oauthProxyImage)
}

func TestParseImageReference(t *testing.T) {
	ref, err := parseImageReference("quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:abc")
	assert.NoError(t, err)
	assert.Equal(t, "quay.io", ref.registry)
	assert.Equal(t, "openshift-release-dev/ocp-v4.0-art-dev", ref.repository)
	assert.Equal(t, "sha256:abc", ref.digest)

	ref, err = parseImageReference("registry.example.com:5000/org/repo:tag1")
	assert.NoError(t, err)
	assert.Equal(t, "registry.example.com:5000", ref.registry)
	assert.Equal(t, "org/repo", ref.repository)
	assert.Equal(t, "tag1", ref.tag)
}

func TestOauthProxyFromImageReferences(t *testing.T) {
	refs := []byte(`
kind: ImageStream
apiVersion: image.openshift.io/v1
spec:
  tags:
  - name: cli
    from:
      kind: DockerImage
      name: example.com/cli@sha256:1
  - name: oauth-proxy
    from:
      kind: DockerImage
      name: quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:503de130
`)
	image, err := oauthProxyFromImageReferences(refs)
	assert.NoError(t, err)
	assert.Equal(t, "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:503de130", image)
}

func TestGetOpenShiftOAuthProxyImageFromReleasePayload(t *testing.T) {
	resetOpenShiftOAuthProxyImageCache()
	infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)

	previousScheme := registryScheme
	registryScheme = "http"
	defer func() { registryScheme = previousScheme }()

	imageReferences := []byte(`
kind: ImageStream
apiVersion: image.openshift.io/v1
spec:
  tags:
  - name: oauth-proxy
    from:
      kind: DockerImage
      name: quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:from-release
`)

	var layerBuf bytes.Buffer
	gz := gzip.NewWriter(&layerBuf)
	tw := tar.NewWriter(gz)
	assert.NoError(t, tw.WriteHeader(&tar.Header{
		Name: releaseImageReferencesPath,
		Mode: 0644,
		Size: int64(len(imageReferences)),
	}))
	_, err := tw.Write(imageReferences)
	assert.NoError(t, err)
	assert.NoError(t, tw.Close())
	assert.NoError(t, gz.Close())
	layerBytes := layerBuf.Bytes()
	layerDigest := "sha256:layer1"

	manifest, err := json.Marshal(map[string]interface{}{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.docker.distribution.manifest.v2+json",
		"layers": []map[string]string{
			{"digest": layerDigest},
		},
	})
	assert.NoError(t, err)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/openshift-release-dev/ocp-release/manifests/sha256:release":
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("Www-Authenticate", `Bearer realm="`+serverURL+`/token",service="registry"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write(manifest)
		case r.URL.Path == "/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
		case r.URL.Path == "/v2/openshift-release-dev/ocp-release/blobs/"+layerDigest:
			_, _ = w.Write(layerBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	host := strings.TrimPrefix(strings.TrimPrefix(server.URL, "https://"), "http://")
	auth := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	cv := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status: configv1.ClusterVersionStatus{
			Desired: configv1.Release{
				Image: host + "/openshift-release-dev/ocp-release@sha256:release",
			},
		},
	}
	pullSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      openShiftPullSecretName,
			Namespace: openShiftPullSecretNamespace,
		},
		Data: map[string][]byte{
			".dockerconfigjson": []byte(`{"auths":{"` + host + `":{"auth":"` + auth + `"}}}`),
		},
	}

	ctx := test.NewCtxBuilder().WithObjects(cv, pullSecret).Build()
	assert.Equal(
		t,
		"quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:from-release",
		getOpenShiftOAuthProxyImage(ctx),
	)
}
