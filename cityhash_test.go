package cityhash

import (
	"testing"
)

type testdata struct {
	input      string
	cityHash64 uint64
  cityHash32 uint32
}

var tests = []testdata{
	{"", 11160318154034397263, 3696677242},
	{"10F70305-2FA8-45EC-886F-21486263BA69", 1267944602943417717, 68969191},
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

func TestCityHash32(t *testing.T) {
	for _, data := range tests {
		out := CityHash32([]byte(data.input))
		if out != data.cityHash32 {
			t.Error(
				"For", data.input,
				"expected", data.cityHash32,
				"got", out,
			)
		}
	}
}
