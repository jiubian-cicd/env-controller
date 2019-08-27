package kube

import (
	"fmt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)


// EnsureDevNamespaceCreatedWithoutEnvironment ensures that there is a development namespace created
func EnsureDevNamespaceCreatedWithoutEnvironment(kubeClient kubernetes.Interface, ns string) error {
	// lets annotate the team namespace as being the developer environment
	labels := map[string]string{
		LabelTeam:        ns,
		LabelEnvironment: LabelValueDevEnvironment,
	}
	annotations := map[string]string{}
	// lets check that the current namespace is marked as the dev environment
	err := EnsureNamespaceCreated(kubeClient, ns, labels, annotations)
	return err
}

// Ensure that the namespace exists for the given name
func EnsureNamespaceCreated(kubeClient kubernetes.Interface, name string, labels map[string]string, annotations map[string]string) error {
	n, err := kubeClient.CoreV1().Namespaces().Get(name, metav1.GetOptions{})
	if err == nil {
		// lets check if we have the labels setup
		if n.Annotations == nil {
			n.Annotations = map[string]string{}
		}
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		changed := false
		if labels != nil {
			for k, v := range labels {
				if n.Labels[k] != v {
					n.Labels[k] = v
					changed = true
				}
			}
		}
		if annotations != nil {
			for k, v := range annotations {
				if n.Annotations[k] != v {
					n.Annotations[k] = v
					changed = true
				}
			}
		}
		if changed {
			_, err = kubeClient.CoreV1().Namespaces().Update(n)
			if err != nil {
				return fmt.Errorf("Failed to label Namespace %s %s", name, err)
			}
		}
		return nil
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      labels,
			Annotations: annotations,
		},
	}
	_, err = kubeClient.CoreV1().Namespaces().Create(namespace)
	if err != nil {
		return fmt.Errorf("Failed to create Namespace %s %s", name, err)
	} else {
		fmt.Sprintf("Namespace %s created ", name)
	}
	return err
}
