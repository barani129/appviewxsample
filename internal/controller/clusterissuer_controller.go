/*
Copyright 2024 baranitharan.chittharajan@spark.co.nz.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	certmv1alpha1 "github.com/barani129/appviewx/api/v1alpha1"
	certmutil "github.com/barani129/appviewx/internal/ClusterIssuer/util"
)

const (
	defaultHealthCheckInterval = time.Minute
)

var (
	errGetAuthSecret    = errors.New("failed to get Secret containing ClusterIssuer credentials")
	errGetAuthConfigmap = errors.New("failed to get Configmap containing intermediate certificate")
)

// ClusterIssuerReconciler reconciles a ClusterIssuer object
type ClusterIssuerReconciler struct {
	client.Client
	Scheme                   *runtime.Scheme
	Kind                     string
	ClusterResourceNamespace string
	recorder                 record.EventRecorder
}

// +kubebuilder:rbac:groups=certm.spark.co.nz,resources=clusterissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certm.spark.co.nz,resources=clusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certm.spark.co.nz,resources=clusterissuers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
func (r *ClusterIssuerReconciler) newIssuer() (client.Object, error) {
	clusterissuerGVK := certmv1alpha1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(clusterissuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ClusterIssuer object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.2/pkg/reconcile
func (r *ClusterIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	_ = log.FromContext(ctx)

	// TODO(user): your logic here
	issuer, err := r.newIssuer()
	if err != nil {
		log.Log.Error(err, "unrecognized issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Log.Info("Clusterissuer is not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := certmutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	// report gives feedback by updating the Ready conidtion of the cluster issuer
	report := func(conditionStatus certmv1alpha1.ConditionStatus, message string, err error) {
		eventType := corev1.EventTypeNormal
		if err != nil {
			log.Log.Error(err, message)
			eventType = corev1.EventTypeWarning
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Log.Info(message)
		}
		r.recorder.Event(issuer, eventType, certmv1alpha1.EventReasonIssuerReconciler, message)
		certmutil.SetReadyCondition(issuerStatus, conditionStatus, certmv1alpha1.EventReasonIssuerReconciler, message)
	}
	defer func() {
		if err != nil {
			report(certmv1alpha1.ConditionFalse, "Temporary error. Retrying...", err)
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := certmutil.GetReadyCondition(issuerStatus); ready == nil {
		report(certmv1alpha1.ConditionUnknown, "First Seen", nil)
		return ctrl.Result{}, nil
	}

	if issuerStatus.LastPollTime == nil {
		log.Log.Info("Checking if remote API is reachable")
		err := certmutil.GetAPIAliveness(issuerSpec)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("remote API is unreachable %s", err)
		}
		now := metav1.Now()
		issuerStatus.LastPollTime = &now
	} else {
		pastTime := time.Now().Add(-2 * time.Minute)
		timeDiff := issuerStatus.LastPollTime.Time.Before(pastTime)
		if timeDiff {
			log.Log.Info("Checking if remote API is rechable as the time elasped")
			err := certmutil.GetAPIAliveness(issuerSpec)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("remote API is unreachable %s", err)
			}
			now := metav1.Now()
			issuerStatus.LastPollTime = &now
		}
	}
	report(certmv1alpha1.ConditionTrue, fmt.Sprintf("Success. Remote API %s is reachable from the cluster.", issuerSpec.URL), nil)
	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor(certmv1alpha1.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(&certmv1alpha1.ClusterIssuer{}).
		Complete(r)
}
