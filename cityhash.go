package cityhash_v1_0_2

/*
#include <stdint.h>
#include "cityhash.h"
*/
import "C"

import (
  "unsafe"
)

func CityHash64(s []byte) uint64 {
  return uint64(C.cityhash64((*C.uint8_t)(unsafe.Pointer(&s[0])), C.size_t(len(s))))
}
