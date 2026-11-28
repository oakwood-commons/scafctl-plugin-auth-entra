package entra

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"unsafe"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func isASCIIAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// validateStoreSecretName enforces both HostService RPC secret-name rules and
// the host encrypted secret backing-store naming contract (1..255 bytes,
// leading ASCII alphanumeric, and only ASCII alphanumeric, '.', '_', or '-').
func validateStoreSecretName(name string) error {
	if err := sdkplugin.ValidateHostSecretName(name); err != nil {
		return err
	}
	if len(name) > 255 {
		return fmt.Errorf("secret name exceeds backing store maximum length of 255")
	}
	if !isASCIIAlphaNum(name[0]) {
		return fmt.Errorf("secret name must start with an ASCII alphanumeric character")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !isASCIIAlphaNum(c) && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("secret name contains invalid backing-store character %q", c)
		}
	}
	return nil
}

// fakeHostService implements proto.HostServiceClient backed by an in-memory map.
type fakeHostService struct {
	mu               sync.Mutex
	secrets          map[string]string
	getSecretFunc    func(ctx context.Context, name string) error
	setSecretErr     error
	setSecretKeyErr  map[string]error
	setSecretFunc    func(ctx context.Context, name, value string) error
	deleteSecretFunc func(ctx context.Context, name string) error
	listSecretsFunc  func(ctx context.Context, pattern string) error
	// promptFunc backs PromptAuthResponse; tests use it to deliver pasted
	// redirect URLs, block until canceled, or return host errors. nil
	// mimics a pre-paste-back host (gRPC Unimplemented).
	promptFunc func(ctx context.Context, req *proto.PromptAuthResponseRequest) (string, error)
	// promptReq captures the most recent PromptAuthResponse request.
	promptReq *proto.PromptAuthResponseRequest
	// promptCalls counts PromptAuthResponse invocations.
	promptCalls int
}

func newFakeHostService() *fakeHostService {
	return &fakeHostService{secrets: make(map[string]string)}
}

// newFakeHostClient creates an sdkplugin.HostServiceClient backed by the fake.
func newFakeHostClient(fake *fakeHostService) *sdkplugin.HostServiceClient {
	hc := &sdkplugin.HostServiceClient{}
	// Inject the fake proto client into the unexported "client" field.
	field := reflect.ValueOf(hc).Elem().FieldByName("client")
	ptr := unsafe.Pointer(field.UnsafeAddr()) //nolint:gosec // intentional: injecting fake into unexported field for testing
	*(*proto.HostServiceClient)(ptr) = fake
	return hc
}

func (f *fakeHostService) GetSecret(ctx context.Context, in *proto.GetSecretRequest, _ ...grpc.CallOption) (*proto.GetSecretResponse, error) {
	if err := validateStoreSecretName(in.Name); err != nil {
		return &proto.GetSecretResponse{Error: fmt.Sprintf("get secret %q: %v", in.Name, err)}, nil
	}

	f.mu.Lock()
	fn := f.getSecretFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Name); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.secrets[in.Name]
	return &proto.GetSecretResponse{Value: v, Found: ok}, nil
}

func (f *fakeHostService) SetSecret(ctx context.Context, in *proto.SetSecretRequest, _ ...grpc.CallOption) (*proto.SetSecretResponse, error) {
	if err := validateStoreSecretName(in.Name); err != nil {
		return &proto.SetSecretResponse{Error: fmt.Sprintf("set secret %q: %v", in.Name, err)}, nil
	}

	f.mu.Lock()
	fn := f.setSecretFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Name, in.Value); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setSecretKeyErr != nil {
		if err, ok := f.setSecretKeyErr[in.Name]; ok && err != nil {
			return nil, err
		}
	}
	if f.setSecretErr != nil {
		return nil, f.setSecretErr
	}
	f.secrets[in.Name] = in.Value
	return &proto.SetSecretResponse{}, nil
}

func (f *fakeHostService) DeleteSecret(ctx context.Context, in *proto.DeleteSecretRequest, _ ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
	if err := validateStoreSecretName(in.Name); err != nil {
		return &proto.DeleteSecretResponse{Error: fmt.Sprintf("delete secret %q: %v", in.Name, err)}, nil
	}

	f.mu.Lock()
	fn := f.deleteSecretFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Name); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, in.Name)
	return &proto.DeleteSecretResponse{}, nil
}

func (f *fakeHostService) ListSecrets(ctx context.Context, in *proto.ListSecretsRequest, _ ...grpc.CallOption) (*proto.ListSecretsResponse, error) {
	var re *regexp.Regexp
	if in.Pattern != "" {
		if len(in.Pattern) > sdkplugin.MaxHostSecretPatternLength {
			return &proto.ListSecretsResponse{
				Error: fmt.Sprintf("pattern too long: max %d characters", sdkplugin.MaxHostSecretPatternLength),
			}, nil
		}
		var err error
		re, err = regexp.Compile(in.Pattern)
		if err != nil {
			return &proto.ListSecretsResponse{
				Error: fmt.Sprintf("invalid pattern: %v", err),
			}, nil
		}
	}

	f.mu.Lock()
	fn := f.listSecretsFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Pattern); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for k := range f.secrets {
		if re == nil || re.MatchString(k) {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	return &proto.ListSecretsResponse{Names: names}, nil
}

func (f *fakeHostService) GetAuthIdentity(_ context.Context, _ *proto.GetAuthIdentityRequest, _ ...grpc.CallOption) (*proto.GetAuthIdentityResponse, error) {
	return &proto.GetAuthIdentityResponse{}, nil
}

func (f *fakeHostService) ListAuthHandlers(_ context.Context, _ *proto.ListAuthHandlersRequest, _ ...grpc.CallOption) (*proto.ListAuthHandlersResponse, error) {
	return &proto.ListAuthHandlersResponse{}, nil
}

func (f *fakeHostService) GetAuthToken(_ context.Context, _ *proto.GetAuthTokenRequest, _ ...grpc.CallOption) (*proto.GetAuthTokenResponse, error) {
	return &proto.GetAuthTokenResponse{}, nil
}

func (f *fakeHostService) GetAuthGroups(_ context.Context, _ *proto.GetAuthGroupsRequest, _ ...grpc.CallOption) (*proto.GetAuthGroupsResponse, error) {
	return &proto.GetAuthGroupsResponse{}, nil
}

// PromptAuthResponse records the request and delegates to promptFunc. The
// default (nil promptFunc) mimics a host built against an older SDK that
// does not implement the RPC, so existing tests keep pre-paste-back
// behavior.
func (f *fakeHostService) PromptAuthResponse(ctx context.Context, in *proto.PromptAuthResponseRequest, _ ...grpc.CallOption) (*proto.PromptAuthResponseResponse, error) {
	f.mu.Lock()
	f.promptCalls++
	f.promptReq = in
	fn := f.promptFunc
	f.mu.Unlock()

	if fn == nil {
		return nil, status.Error(codes.Unimplemented, "PromptAuthResponse not implemented")
	}
	value, err := fn(ctx, in)
	if err != nil {
		return nil, err
	}
	return &proto.PromptAuthResponseResponse{Value: value}, nil
}

// promptRequest returns the most recent PromptAuthResponse request and the
// number of calls, mutex-guarded for assertions after Login returns.
func (f *fakeHostService) promptRequest() (*proto.PromptAuthResponseRequest, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.promptReq, f.promptCalls
}
