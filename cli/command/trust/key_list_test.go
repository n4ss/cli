package trust

import (
	"testing"

	command "github.com/docker/cli/cli/command"
)

func Test_listKeys(t *testing.T) {
	type args struct {
		dockerCli command.Streams
		options   keyListOptions
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := listKeys(tt.args.dockerCli, tt.args.options); (err != nil) != tt.wantErr {
				t.Errorf("listKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
