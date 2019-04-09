package cityhash

/*
#include <stdint.h>
#include "cityhash.h"
*/
import "C"

import (
  "unsafe"
)

func CityHash64(s []byte) uint64 {
  if len(s) == 0 {
    return uint64(C.cityhash64((*C.uint8_t)(C.NULL), 0))
  }
  return uint64(C.cityhash64((*C.uint8_t)(unsafe.Pointer(&s[0])), C.size_t(len(s))))
}

func CityHash32(s []byte) uint32 {
  if len(s) == 0 {
    return uint32(C.cityhash32((*C.uint8_t)(C.NULL), 0))
  }
  return uint32(C.cityhash32((*C.uint8_t)(unsafe.Pointer(&s[0])), C.size_t(len(s))))
}
