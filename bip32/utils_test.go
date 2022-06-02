package bip32

import (
	"reflect"
	"testing"
)

func Test_uint32ToBytes(t *testing.T) {
	type args struct {
		i uint32
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "uint32ToBytes",
			args: args{
				i: 0x01020304,
			},
			want: []byte{0x04, 0x03, 0x02, 0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uint32ToBytes(tt.args.i); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("uint32ToBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hashSha256(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "",
			args: args{
				data: []byte{0x01, 0x02, 0x03, 0x04},
			},
			want:    []byte{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hashSha256(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("hashSha256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("hashSha256() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hashDoubleSha256(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "",
			args: args{
				data: []byte{0x01, 0x02, 0x03, 0x04},
			},
			want:    []byte{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hashDoubleSha256(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("hashDoubleSha256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("hashDoubleSha256() got = %v, want %v", got, tt.want)
			}
		})
	}
}
