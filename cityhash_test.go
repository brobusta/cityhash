package cityhash_v1_0_2

import (
	"testing"
)

type testdata struct {
	input      string
	cityHash64 uint64
}

var tests = []testdata{
	{"", 11160318154034397263},
	{"10F70305-2FA8-45EC-886F-21486263BA69", 3190139111445150629},
}

func TestCityHash64(t *testing.T) {
	for _, data := range tests {
		out := CityHash64([]byte(data.input))
		if out != data.cityHash64 {
			t.Error(
				"For", data.input,
				"expected", data.cityHash64,
				"got", out,
			)
		}
	}
}
