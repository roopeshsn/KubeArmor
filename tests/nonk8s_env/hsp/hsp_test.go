package hsp_test

import (
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HSP Systemd Mode", func() {
	Describe("HSP file path audit", func() {
		It("Audit access to /etc/passwd resource on the host mode", func() {
			// listen to events
			err := KarmorLogStart("policy", "", "File", "")
			Expect(err).To(BeNil())

			policyPath := "res/hsp-kubearmor-dev-file-path-audit.yaml"
			err1 := SendPolicy("ADDED", policyPath)
			Expect(err1).To(BeNil())

			// try to access the /etc/passwd resource
			out, err := ExecuteCommand([]string{"bash", "-c", "cat /etc/passwd"})
			Expect(err).To(BeNil())
			Expect(out).NotTo(BeNil())

			// get alert and check whether the action is audit
			_, alerts, err := KarmorGetLogs(10*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-file-path-audit"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Audit"))

			// deleting the policy
			err2 := SendPolicy("DELETED", policyPath)
			Expect(err2).To(BeNil())

			KarmorLogStop()
		})
	})

	Describe("HSP file path block - date", func() {
		It("Block access to date resource on the host mode", func() {
			// listen to events
			err := KarmorLogStart("policy", "", "File", "")
			Expect(err).To(BeNil())

			policyPath := "res/hsp-kubearmor-dev-proc-path-block-fromSource.yaml"
			err1 := SendPolicy("ADDED", policyPath)
			Expect(err1).To(BeNil())

			// try to access the date resource
			out, err := ExecuteCommand([]string{"bash", "-c", "date"})
			Expect(err).To(BeNil())
			Expect(out).To(MatchRegexp(".*Permission denied"))

			// get alert and check whether the action is block
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-proc-path-block-fromSource"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Block"))

			// deleting the policy
			err2 := SendPolicy("DELETED", policyPath)
			Expect(err2).To(BeNil())

			KarmorLogStop()
		})
	})
})