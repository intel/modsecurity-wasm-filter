/*
Copyright 2022.

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

package controllers

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	modsecurityv1 "intel.com/ruleserver/api/v1"
)

const (
	SelectApp = ".spec.selector.matchLabels"
	appLabel  = "app"
)

// RuleReconciler reconciles a Rule object
type RuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=modsecurity.intel.com,resources=rules,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=modsecurity.intel.com,resources=rules/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=modsecurity.intel.com,resources=rules/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Rule object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *RuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// TODO(user): your logic here

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &modsecurityv1.Rule{}, SelectApp, func(rawObj client.Object) []string {

		rule := rawObj.(*modsecurityv1.Rule)

		app, ok := rule.Spec.Selector.MatchLabels[appLabel]
		if !ok {
			return nil
		}
		return []string{app}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&modsecurityv1.Rule{}).
		Complete(r)
}
