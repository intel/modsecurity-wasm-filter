package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	modsecurityv1 "intel.com/ruleserver/api/v1"
	"intel.com/ruleserver/controllers"
)

// rule server
type Server struct {
	Addr string
	Ctx  context.Context
	Mgr  *ctrl.Manager
	Log  logr.Logger
}

func (s *Server) Serve() error {
	var err error
	mux := http.NewServeMux()
	mux.Handle("/", s.ServerHandler())

	srv := &http.Server{
		Addr:    s.Addr,
		Handler: mux,
	}

	go func() {
		if err = srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.Log.Error(err, "listen failed")
		}
	}()

	s.Log.Info("server started")

	<-s.Ctx.Done()

	s.Log.Info("server stopped")

	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	if err = srv.Shutdown(ctxShutDown); err != nil {
		s.Log.Error(err, "failed to shutdown server")
		return err
	}

	s.Log.Info("server exited properly")

	if err == http.ErrServerClosed {
		err = nil
	}

	return err
}

func (s *Server) ServerHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		namespacedApp, err := getNamespacedApp(r.URL.Path[1:])
		if err != nil {
			s.Log.Error(err, "invalid request")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(nil)
		}
		var (
			ruleList   modsecurityv1.RuleList
			configList modsecurityv1.ConfigList
			response   string
		)
		mgrClient := (*s.Mgr).GetClient()

		err = mgrClient.List(context.TODO(), &configList, client.InNamespace(namespacedApp.Namespace), client.MatchingFields{controllers.SelectApp: namespacedApp.App})
		if err != nil {
			s.Log.Error(err, "config not found")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(nil)
		}

		if len(configList.Items) != 1 {
			s.Log.Error(err, "invalid config")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(nil)
		}

		for _, config := range strings.Split(configList.Items[0].Spec.Configs, "\n") {
			if strings.Contains(config, "\\") {
				for _, subconfig := range strings.SplitAfter(config, "\\ ") {
					response = response + subconfig + "\n"
				}
				response += "\n\n"
			} else {
				response = response + config + "\n\n"
			}
		}

		err = mgrClient.List(context.TODO(), &ruleList, client.InNamespace(namespacedApp.Namespace), client.MatchingFields{controllers.SelectApp: namespacedApp.App})
		if err != nil {
			s.Log.Error(err, "rule not found")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(nil)
		}

		for _, rule := range strings.Split(ruleList.Items[0].Spec.Rules, "\n") {
			if strings.Contains(rule, "\\") {
				for _, subrule := range strings.SplitAfter(rule, "\\ ") {
					response = response + subrule + "\n"
				}
				response += "\n\n"
			} else {
				response = response + rule + "\n\n"
			}
		}

		_, _ = w.Write([]byte(response))
	}
}

const (
	Separator = "/"
)

type NamespacedApp struct {
	Namespace string
	App       string
}

func getNamespacedApp(key string) (NamespacedApp, error) {
	array := strings.Split(key, Separator)
	if len(array) != 2 {
		return NamespacedApp{}, fmt.Errorf("invalid key")
	}
	return NamespacedApp{Namespace: array[0], App: array[1]}, nil
}
