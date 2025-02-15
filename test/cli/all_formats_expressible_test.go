package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/format"
)

func TestAllFormatsExpressible(t *testing.T) {
	commonAssertions := []traitAssertion{
		func(tb testing.TB, stdout, _ string, _ int) {
			tb.Helper()
			if len(stdout) < 1000 {
				tb.Errorf("there may not be any report output (len=%d)", len(stdout))
			}
		},
		assertSuccessfulReturnCode,
	}

	for _, o := range format.AllOptions {
		t.Run(fmt.Sprintf("format:%s", o), func(t *testing.T) {
			cmd, stdout, stderr := runSyft(t, nil, "dir:./test-fixtures/image-pkg-coverage", "-o", string(o))
			for _, traitFn := range commonAssertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			if t.Failed() {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
			}
		})
	}
}
