package bip39

import "testing"

func Test_entropyChecksumBinStr(t *testing.T) {
	type args struct {
		slice []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test1",
			args: args{
				slice: []byte{},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := entropyCheckSumBinStr(tt.args.slice); got != tt.want {
				t.Errorf("entropyChecksumBinStr() = %v, want %v", got, tt.want)
			}
		})
	}
}
