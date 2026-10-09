package workloadkeyproviderv1_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	workloadkeyproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadkeyprovider/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestWorkloadKeyProviderContractContainsOnlyOpaqueKeyMaterial(t *testing.T) {
	protoPath := filepath.Join("workloadkeyprovider.proto")
	contents, err := os.ReadFile(protoPath)
	require.NoError(t, err)

	contract := string(contents)
	for _, required := range []string{
		"service WorkloadKeyProvider",
		"rpc GenerateKey",
		"rpc Sign",
		"rpc ReleaseKey",
		"bytes key_reference",
		"bytes public_key",
		"uint64 generation",
	} {
		require.Contains(t, contract, required)
	}

	privateKeyField := regexp.MustCompile(`(?m)^\s*(bytes|string)\s+(private_key|pkcs8|pfx)\s*=`)
	require.False(t, privateKeyField.MatchString(contract))
	require.NotContains(t, strings.ToLower(contract), "exportprivate")
	for _, forbidden := range []string{
		"hse",
		"keyguard",
		"ncrypt",
		"software ksp",
		"servicetree",
		"local_cng",
		"agent_sign_rpc",
	} {
		require.NotContains(t, strings.ToLower(contract), forbidden)
	}
}

func TestGeneratedWorkloadKeyProviderAPIAndPluginWrapper(t *testing.T) {
	client := workloadkeyproviderv1.WorkloadKeyProviderPluginClient{}
	require.Equal(t, "WorkloadKeyProvider", client.Type())
	require.Equal(t, "spire.plugin.agent.workloadkeyprovider.v1.WorkloadKeyProvider", client.GRPCServiceName())

	fields := (&workloadkeyproviderv1.GenerateKeyResponse{}).ProtoReflect().Descriptor().Fields()
	require.NotNil(t, fields.ByName(protoreflect.Name("key_reference")))
	require.NotNil(t, fields.ByName(protoreflect.Name("public_key")))
	require.NotNil(t, fields.ByName(protoreflect.Name("generation")))
	for _, forbidden := range []protoreflect.Name{"private_key", "pkcs8", "pfx"} {
		require.Nil(t, fields.ByName(forbidden))
	}
}
