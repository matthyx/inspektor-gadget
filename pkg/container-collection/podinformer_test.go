package containercollection

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func BenchmarkProcessNextItem(b *testing.B) {
	config, err := clientcmd.BuildConfigFromFlags("", "/home/mbertschy/.kube/config")
	if err != nil {
		panic(err)
	}
	clientset := kubernetes.NewForConfigOrDie(config)
	// benchmark the rest client
	b.Run("REST client", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = clientset.CoreV1().RESTClient().Get().Namespace("default").Resource("pods").Name("example-deployment-1-656bb96dc9-24fk6").Do(context.TODO()).Get()
		}
		b.ReportAllocs()
	})
	// benchmark the regular client
	b.Run("regular client", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = clientset.CoreV1().Pods("default").Get(context.TODO(), "example-deployment-1-656bb96dc9-24fk6", metav1.GetOptions{})
		}
		b.ReportAllocs()
	})
}
