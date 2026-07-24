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
	"sync"
	"time"

	"github.com/eclipse-che/che-operator/pkg/common/chetypes"
	defaults "github.com/eclipse-che/che-operator/pkg/common/operator-defaults"
	ctrl "sigs.k8s.io/controller-runtime"
)

var openShiftOAuthProxyImageLog = ctrl.Log.WithName("openshift-oauth-proxy-image")

// releaseLookupRetryInterval is how long to wait before retrying a failed release-payload
// lookup. Successful resolves are cached for the lifetime of the process.
const releaseLookupRetryInterval = 10 * time.Minute

var (
	cachedOpenShiftOAuthProxyImage string
	nextReleaseLookupAllowed       time.Time
	openShiftOAuthProxyImageMu     sync.Mutex
)

// resetOpenShiftOAuthProxyImageCache is for unit tests only.
func resetOpenShiftOAuthProxyImageCache() {
	openShiftOAuthProxyImageMu.Lock()
	defer openShiftOAuthProxyImageMu.Unlock()
	cachedOpenShiftOAuthProxyImage = ""
	nextReleaseLookupAllowed = time.Time{}
}

// getOpenShiftOAuthProxyImage returns the oauth-proxy image for the Che gateway on OpenShift.
//
// Precedence (highest first):
//  1. CheCluster gateway container image override — applied later by OverrideDeployment
//  2. OpenShift release payload oauth-proxy (equivalent to:
//     oc adm release info --image-for=oauth-proxy), cached after success
//  3. RELATED_IMAGE_gateway_authentication_sidecar
//
// Note: when release resolution succeeds, an admin patch of RELATED_IMAGE alone no longer
// overrides the gateway image; use the CheCluster container override instead.
// See https://github.com/eclipse-che/che/issues/23895
func getOpenShiftOAuthProxyImage(ctx *chetypes.DeployContext) string {
	openShiftOAuthProxyImageMu.Lock()
	if cachedOpenShiftOAuthProxyImage != "" {
		image := cachedOpenShiftOAuthProxyImage
		openShiftOAuthProxyImageMu.Unlock()
		return image
	}
	shouldLookupRelease := time.Now().After(nextReleaseLookupAllowed)
	if shouldLookupRelease {
		// Block concurrent retries until this attempt finishes.
		nextReleaseLookupAllowed = time.Now().Add(releaseLookupRetryInterval)
	}
	openShiftOAuthProxyImageMu.Unlock()

	if shouldLookupRelease {
		if image := findOpenShiftOAuthProxyImageFromRelease(ctx); image != "" {
			cacheOpenShiftOAuthProxyImage(image)
			return image
		}
		openShiftOAuthProxyImageLog.Info(
			"could not resolve oauth-proxy from OpenShift release payload; using RELATED_IMAGE_gateway_authentication_sidecar",
			"retryAfter", releaseLookupRetryInterval.String(),
		)
	}

	return defaults.GetGatewayOpenShiftAuthenticationSidecarImage(ctx.CheCluster)
}

func cacheOpenShiftOAuthProxyImage(image string) {
	openShiftOAuthProxyImageMu.Lock()
	defer openShiftOAuthProxyImageMu.Unlock()
	cachedOpenShiftOAuthProxyImage = image
}
