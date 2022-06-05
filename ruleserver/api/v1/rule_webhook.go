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

package v1

import (
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var rulelog = logf.Log.WithName("rule-resource")

func (r *Rule) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

//+kubebuilder:webhook:path=/mutate-modsecurity-intel-com-v1-rule,mutating=true,failurePolicy=fail,sideEffects=None,groups=modsecurity.intel.com,resources=rules,verbs=create;update,versions=v1,name=mrule.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &Rule{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *Rule) Default() {
	rulelog.Info("default", "name", r.Name)

	if len(r.Spec.Rules) == 0 {
		r.Spec.Rules = "SecRule ARGS:param1 \"test\" \"id:1,phase:1,log,status:200,msg:'Test rule'\"\nSecRule ARGS:param1 \"attack\" \"id:2,phase:1,deny,status:400,msg:'Test rule'\""
		rulelog.Info("Rules are empty, set default value now", "Rules", r.Spec.Rules)
	} else {
		if strings.Contains(r.Spec.Rules, "@pmFromFile") {
			r.Spec.Rules = strings.ReplaceAll(r.Spec.Rules, "@pmFromFile", "@pm")
			rulelog.Info("Replace @pmFromFile with @pm")
		}
		rulelog.Info("Rules exist", "Rules", r.Spec.Rules)
	}

}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-modsecurity-intel-com-v1-rule,mutating=false,failurePolicy=fail,sideEffects=None,groups=modsecurity.intel.com,resources=rules,verbs=create;update,versions=v1,name=vrule.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &Rule{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *Rule) ValidateCreate() error {
	rulelog.Info("validate create", "name", r.Name)

	// TODO(user): fill in your validation logic upon object creation.
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *Rule) ValidateUpdate(old runtime.Object) error {
	rulelog.Info("validate update", "name", r.Name)

	// TODO(user): fill in your validation logic upon object update.
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *Rule) ValidateDelete() error {
	rulelog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}
